#!/usr/bin/env python3
"""round67 — Short key brute-force + container/overlay IDs as PROBE_SECRET"""
import hmac as hm, hashlib, time, struct, itertools, string

KNOWN_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

ALL_PAIRS = [
    (b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")),
    (b"http://gauge-gw.internal:9100/v1/tanks/1/level",
     bytes.fromhex("ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803")),
]

def check_key(key_bytes):
    return hm.new(key_bytes, KNOWN_URL, hashlib.sha256).digest() == KNOWN_SIG

def verify_all(key_bytes):
    for url, sig in ALL_PAIRS:
        if hm.new(key_bytes, url, hashlib.sha256).digest() != sig:
            return False
    return True

# ============================================================
print("="*70)
print("PHASE 1: ALL BINARY KEYS 1-3 BYTES")
print("="*70)

# 1 byte: 256
print("  Testing 1-byte keys (256)...")
t0 = time.time()
for i in range(256):
    key = bytes([i])
    if check_key(key):
        print(f"  *** FOUND 1-byte: {key!r} (0x{i:02x}) ***")
        if verify_all(key):
            print(f"  *** CONFIRMED AGAINST ALL PAIRS! ***")
        break
else:
    print(f"  No match ({time.time()-t0:.1f}s)")

# 2 bytes: 65536
print("  Testing 2-byte keys (65536)...")
t0 = time.time()
for i in range(65536):
    key = struct.pack('>H', i)
    if check_key(key):
        print(f"  *** FOUND 2-byte: {key!r} (0x{i:04x}) ***")
        if verify_all(key):
            print(f"  *** CONFIRMED! ***")
        break
else:
    print(f"  No match ({time.time()-t0:.1f}s)")

# 3 bytes: 16,777,216
print("  Testing 3-byte keys (16.7M)...")
t0 = time.time()
found = False
for i in range(16777216):
    key = struct.pack('>I', i)[1:]  # 3 bytes big-endian
    if check_key(key):
        print(f"  *** FOUND 3-byte: {key!r} (0x{i:06x}) ***")
        if verify_all(key):
            print(f"  *** CONFIRMED! ***")
        found = True
        break
    if i % 2000000 == 0 and i > 0:
        elapsed = time.time() - t0
        rate = i / elapsed
        print(f"    {i:>10,} / 16,777,216 | {rate:,.0f}/sec | {elapsed:.0f}s")

if not found:
    print(f"  No match ({time.time()-t0:.0f}s)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: CONTAINER/INFRASTRUCTURE IDS AS PROBE_SECRET")
print("="*70)

container_full = "5407f6317f5cb1c5e178d2edd9fe960f73126e60833d9c1f297d13d9ddeb1e75"
container_short = "5407f6317f5c"

infra_candidates = [
    # Container IDs
    container_full,
    container_short,
    container_full[:32],  # First half
    container_full[32:],  # Second half
    # Overlay snapshot IDs
    "74", "53", "52", "18", "17", "16", "15", "14", "13", "12", "77",
    # Overlay combinations
    "74-53-52-18-17-16-15-14-13-12",
    "77",
    # MAC addresses
    "66:79:04:3f:68:8e",
    "36:28:d3:f8:30:c7",
    "a6:07:72:0b:6a:4a",
    "667904_3f688e",
    "3628d3f830c7",
    "a607720b6a4a",
    # Docker volume names
    "khs-oil-depot_lfiflagvol",
    "khs-oil-depot_xxeflagvol",
    "khs-oil-depot",
    "oil-depot",
    "oil_depot",
    # Docker project + container
    "khs-oil-depot_caspiterminal",
    "caspiterminal",
    "caspi-terminal",
    "CaspiTerminal",
    "caspi_terminal",
    "terminal",
    # Network info
    "172.18.0.5",
    "172.18.0.3",
    "172.18.0.4",
    "172.18.0.7",
    "gauge-gw.internal",
    "gauge-gw",
    "terminal-db",
    # inode numbers from /proc/net/tcp
    "17812676",
    "17814223",
    # Kernel version
    "7.0.0-34-generic",
    # Process info
    "gunicorn",
    # Ports
    "3000",
    "8007",
    "9000",
    "9100",
    # Common CTF patterns
    "flag", "FLAG", "secret", "SECRET",
    "probe_secret", "PROBE_SECRET",
    "llehs", "LLEHS", "shell", "SHELL",
    "reverse", "REVERSE",
    "kazhackstan", "KazHackStan", "KAZHACKSTAN",
    "khs", "KHS",
    "ctf", "CTF",
    "oil", "OIL", "depot", "DEPOT",
    # Hex of "llehs"
    "6c6c656873",
    # Base64 of "shell"
    "c2hlbGw=",
    # SHA256 of container ID
    hashlib.sha256(container_full.encode()).hexdigest(),
    hashlib.sha256(container_short.encode()).hexdigest(),
    # MD5 of container ID
    hashlib.md5(container_full.encode()).hexdigest(),
    hashlib.md5(container_short.encode()).hexdigest(),
    # Database-style connection strings
    "postgresql://postgres:postgres@terminal-db:5432/terminal",
    "postgresql://postgres:postgres@terminal-db:5432/caspiterminal",
    "postgresql://caspiterminal:caspiterminal@terminal-db:5432/terminal",
    "postgresql://admin:admin@terminal-db:5432/terminal",
    # UUID patterns
    "5407f631-7f5c-b1c5-e178-d2edd9fe960f",
    # OT/SCADA terms
    "modbus", "opcua", "scada",
    "loading-arm-1", "loading_arm_1",
    # Combined with project
    "khs-oil-depot-probe",
    "khs-oil-depot-secret",
    "khs-probe-secret",
    # CaspiTerminal related
    "CaspiTerminal2026",
    "caspi2026",
    "Caspi2026!",
    "caspiterminal2026",
    # Patterns from flags
    "c8142af02727b3d7d51e4aece866104b",  # STF flag hash
    "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",  # KHS flag hash
    # Reversed strings
    "lanimreTipsaC",
    "topedlio",
    # Common defaults
    "supersecret", "super_secret", "SuperSecret",
    "mysecret", "my_secret", "MySecret",
    "hmac_secret", "hmac-secret", "HmacSecret",
    "signing_key", "signing-key", "SigningKey",
    "probe_key", "probe-key", "ProbeKey",
    "gauge_secret", "gauge-secret",
    "oilgassecret", "oil-gas-secret",
]

for c in infra_candidates:
    for variant in [c, c + '\n']:
        key = variant.encode('utf-8')
        if check_key(key):
            print(f"  *** FOUND: '{c}' (with_newline={variant.endswith(chr(10))}) ***")
            if verify_all(key):
                print(f"  *** CONFIRMED AGAINST ALL PAIRS! ***")
            break

print(f"  Tested {len(infra_candidates)} candidates (x2 with newline)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PRINTABLE ASCII KEYS 1-5 CHARS")
print("="*70)

printable = string.ascii_letters + string.digits + string.punctuation

# 1-3 chars: very fast
for length in range(1, 4):
    count = len(printable) ** length
    print(f"  Testing {length}-char printable ({count:,})...")
    t0 = time.time()
    found = False
    tested = 0
    for combo in itertools.product(printable, repeat=length):
        key = ''.join(combo).encode('ascii')
        tested += 1
        if check_key(key):
            print(f"  *** FOUND {length}-char: {''.join(combo)!r} ***")
            if verify_all(key):
                print(f"  *** CONFIRMED! ***")
            found = True
            break
    if not found:
        print(f"    No match ({time.time()-t0:.1f}s, {tested:,} tested)")

# 4 chars with reduced charset (lowercase + digits only = 36^4 = 1.7M)
print(f"  Testing 4-char alphanum-lower (1,679,616)...")
t0 = time.time()
found = False
charset_small = string.ascii_lowercase + string.digits
tested = 0
for combo in itertools.product(charset_small, repeat=4):
    key = ''.join(combo).encode('ascii')
    tested += 1
    if check_key(key):
        print(f"  *** FOUND 4-char: {''.join(combo)!r} ***")
        if verify_all(key):
            print(f"  *** CONFIRMED! ***")
        found = True
        break
    if tested % 500000 == 0:
        elapsed = time.time() - t0
        print(f"    {tested:>10,} / 1,679,616 | {tested/elapsed:,.0f}/sec")
if not found:
    print(f"    No match ({time.time()-t0:.1f}s)")

# 5 chars lowercase-only (26^5 = 11.8M)
print(f"  Testing 5-char lowercase (11,881,376)...")
t0 = time.time()
found = False
tested = 0
for combo in itertools.product(string.ascii_lowercase, repeat=5):
    key = ''.join(combo).encode('ascii')
    tested += 1
    if check_key(key):
        print(f"  *** FOUND 5-char: {''.join(combo)!r} ***")
        if verify_all(key):
            print(f"  *** CONFIRMED! ***")
        found = True
        break
    if tested % 3000000 == 0:
        elapsed = time.time() - t0
        print(f"    {tested:>10,} / 11,881,376 | {tested/elapsed:,.0f}/sec")
if not found:
    print(f"    No match ({time.time()-t0:.1f}s)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: HEX STRING KEYS (2-12 HEX CHARS)")
print("="*70)

for hex_len in range(2, 13, 2):  # 2,4,6,8,10,12 hex chars
    byte_len = hex_len // 2
    total = 256 ** byte_len
    if total > 20_000_000:
        print(f"  Skipping {hex_len} hex chars ({total:,} — too many)")
        continue
    print(f"  Testing {hex_len} hex chars ({total:,})...")
    t0 = time.time()
    found = False
    for i in range(total):
        key_hex = f"{i:0{hex_len}x}"
        key = key_hex.encode('ascii')
        if check_key(key):
            print(f"  *** FOUND hex key: '{key_hex}' ***")
            if verify_all(key):
                print(f"  *** CONFIRMED! ***")
            found = True
            break
        # Also try the binary representation
        key_bin = bytes.fromhex(key_hex)
        if hm.new(key_bin, KNOWN_URL, hashlib.sha256).digest() == KNOWN_SIG:
            print(f"  *** FOUND binary hex: {key_bin!r} (hex: {key_hex}) ***")
            found = True
            break
    if not found:
        print(f"    No match ({time.time()-t0:.1f}s)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: WORDLIST — COMMON SECRETS & CTF PATTERNS")
print("="*70)

# Extended wordlist based on all known information
words = [
    # Standard secrets
    "password", "secret", "changeme", "admin", "root",
    "P@ssw0rd", "pa$$word", "passw0rd", "letmein", "welcome",
    "default", "test", "testing", "demo", "development",
    # Oil/gas/terminal themed
    "oildepot", "oil-depot", "oil_depot",
    "oilgas", "oil-gas", "oil_gas",
    "pipeline", "refinery", "tanker", "cargo",
    "custody", "transfer", "loading",
    "barrel", "crude", "diesel", "kerosene",
    "brent", "wti", "opec",
    # Kazakhstan themed
    "astana", "almaty", "nursultan", "atyrau", "aktau",
    "mangystau", "tengiz", "kashagan", "karachaganak",
    "tengizchevroil", "chevron", "shell", "total",
    "kazmunaigaz", "kmg", "KMG",
    # Caspian sea themed
    "caspian", "Caspian", "CASPIAN",
    "caspisea", "caspian-sea", "caspian_sea",
    "khazar", "Khazar", "KHAZAR",
    # CTF themed
    "kazhackstan2026", "KazHackStan2026",
    "khs2026", "KHS2026",
    "ctf2026", "CTF2026",
    "hackathon", "hacking",
    "challenge", "flag{}", "flag",
    # Technical
    "hmac256", "sha256", "hs256",
    "jwt_secret", "jwt-secret", "JWTSecret",
    "api_key", "api-key", "ApiKey",
    "bearer", "token", "auth",
    # SCADA/ICS
    "scada", "SCADA", "Scada",
    "modbus", "opcua", "dnp3",
    "plc", "hmi", "dcs", "rtu",
    "ics", "ICS", "ot", "OT",
    # Gauge related
    "gauge", "meter", "sensor",
    "flow_meter", "level_sensor",
    "loading_arm", "tank_gauge",
    # Numbers
    "123456", "12345678", "1234567890",
    "111111", "000000", "654321",
    # Combinations
    "caspiterminal_probe", "probe_caspiterminal",
    "ct_probe_secret", "ct-probe-secret",
    "khs_oil_depot_probe", "probe_secret_2026",
    "CaspiProbe", "caspiprobe",
    "OilDepotProbe", "oildepotprobe",
    "GaugeSecret", "gaugesecret",
    "ProbeHMAC", "probehmac",
    "SigningSecret", "signingsecret",
    "HMAC_KEY", "hmac_key",
    "SIGNING_KEY", "signing_key",
]

found = False
for w in words:
    for variant in [w, w + '\n', w.encode('utf-8').hex()]:
        key = variant.encode('utf-8') if isinstance(variant, str) else variant
        if check_key(key):
            print(f"  *** FOUND: {w!r} ***")
            if verify_all(key):
                print(f"  *** CONFIRMED! ***")
            found = True
            break
    if found:
        break

if not found:
    print(f"  No match in {len(words)} words")

print("\n"+"="*70)
print("DONE")
print("="*70)
