import ftplib
import smtplib
import poplib
import imaplib
import socket
import os
import time
import threading
import shutil
import requests
import config

# --- IMPORTS ---
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

try:
    from scapy.all import sniff, wrpcap, rdpcap, sendp, IP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] Scapy не установлен.")

# --- CONFIG ---
HOST = config.LAB_SERVER_IP
SECRET = config.SECRET_DATA
RESULTS_DIR = "test_results"

if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

def log(msg): print(f"[AUDIT] {msg}")

# ===========================
# 1. СНИФФЕР (ИСПРАВЛЕННЫЙ)
# ===========================
stop_sniffer = threading.Event()

def traffic_sniffer():
    if not HAS_SCAPY: return
    pcap_file = os.path.join(RESULTS_DIR, "session_dump.pcap")
    
    # Фильтр: только наш сервер
    bpf_filter = f"host {HOST}"
    log(f"🔴 [SNIFFER] Старт. Фильтр: {bpf_filter}")
    
    packets = []
    
    # ЦИКЛ: Читаем по 1 секунде, проверяем флаг стоп
    # Это решает проблему бесконечного зависания
    while not stop_sniffer.is_set():
        try:
            # timeout=1 позволяет скрипту "просыпаться" и проверять stop_sniffer
            pkts = sniff(filter=bpf_filter, timeout=1)
            packets.extend(pkts)
        except Exception:
            pass # Игнорируем ошибки интерфейса
            
    # Сохраняем
    if packets:
        wrpcap(pcap_file, packets)
        log(f"✅ [SNIFFER] Сохранено {len(packets)} пакетов.")
    else:
        log("⚠️ [SNIFFER] Пакеты не перехвачены (возможно, не тот интерфейс или IP).")

# ===========================
# 2. XMPP (RAW SOCKET)
# ===========================
def test_xmpp_raw():
    log("=== XMPP (Jabber) TEST ===")
    try:
        # 1. Подключаемся
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, 5222))
        
        # 2. Формируем XMPP приветствие (Handshake)
        # Это стандартный заголовок любого Jabber клиента
        stream_header = f"<stream:stream to='{HOST}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>".encode()
        s.send(stream_header)
        
        # Читаем ответ сервера (он должен прислать свой stream ID)
        try:
            resp = s.recv(4096)
            # log(f"   [DEBUG] Server hello: {resp}") # Раскомментируй для отладки
        except socket.timeout:
            pass

        # 3. ОТПРАВЛЯЕМ СЕКРЕТ
        # Мы шлем сообщение без авторизации. 
        # Сервер его скорее всего отвергнет ошибкой, НО сам пакет с текстом
        # "LEAK: ..." физически уйдет в провод. Этого достаточно для DLP.
        
        msg_body = f"""
<message to='admin@{HOST}' type='chat'>
  <body>XMPP LEAK CHECK: {SECRET}</body>
</message>
"""
        s.send(msg_body.encode())
        log(f"   [XMPP] 📤 Пакет с сообщением отправлен (Raw Socket).")
        
        # Корректно закрываем поток
        s.send(b"</stream:stream>")
        time.sleep(0.5)
        s.close()
        
        log(f"   [XMPP] ✅ Тест завершен.")
        
    except Exception as e:
        log(f"   [XMPP] ❌ Fail: {e}")

# ===========================
# 3. EMAIL (ИСПРАВЛЕННЫЙ)
# ===========================
def test_email_cycle():
    log(f"=== EMAIL TEST ===")
    try:
        # A. SMTP (Отправка)
        # Мы отключили auth в GreenMail, поэтому login не обязателен, 
        # но для DLP лучше, чтобы он был.
        s = smtplib.SMTP(HOST, 25)
        try:
            s.login("user", "pass") # Пробуем, если сервер пустит
        except:
            pass # Если ошибка - шлем без логина (GreenMail примет)
            
        msg = f"Subject: LEAK\nFrom: attacker@test\nTo: user@test\n\n{SECRET}"
        s.sendmail("attacker@test", "user@test", msg.encode('utf-8'))
        s.quit()
        log("   [SMTP] ⬆️ Письмо отправлено.")
        
        time.sleep(1)
        
        # B. POP3 (Получение)
        p = poplib.POP3(HOST, 110)
        p.user("user")
        p.pass_("pass")
        count = len(p.list()[1])
        if count > 0:
            # Скачиваем последнее
            lines = p.retr(count)[1]
            full_msg = b"\n".join(lines).decode('utf-8', errors='ignore')
            
            with open(os.path.join(RESULTS_DIR, "email.eml"), "w") as f:
                f.write(full_msg)
            
            if SECRET in full_msg:
                log("   [POP3] ✅ Письмо получено и секрет внутри.")
            else:
                log("   [POP3] ⚠️ Письмо есть, но секрета нет.")
        else:
            log("   [POP3] ❌ Ящик пуст.")
        p.quit()
        
    except Exception as e:
        log(f"   [EMAIL] Fail: {e}")

# ===========================
# 4. SIP & ДРУГИЕ
# ===========================
def test_sip_voip():
    log(f"=== SIP/VoIP TEST ===")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Уникальный Call-ID
        cid = int(time.time())
        invite = f"INVITE sip:100@{HOST} SIP/2.0\r\nCall-ID: {cid}\r\nFrom: auditor\r\n".encode()
        sock.sendto(invite, (HOST, 5060))
        
        log("   [SIP] 📞 Звонок (RTP поток)...")
        # RTP
        for i in range(550): # Чуть меньше 11 сек
            sock.sendto(os.urandom(160), (HOST, 10000))
            time.sleep(0.02)
        sock.close()
        
        log("   [SIP] 🏁 Ждем сохранения файла (5 сек)...")
        time.sleep(5) 
        
        # Скачивание
        url = f"http://{HOST}/recordings/dlp_record.wav"
        save_path = os.path.join(RESULTS_DIR, "call_evidence.wav")
        
        r = requests.get(url)
        if r.status_code == 200:
            with open(save_path, 'wb') as f: f.write(r.content)
            log(f"   [SIP] ✅ УСПЕХ: Файл скачан ({len(r.content)} байт).")
        else:
            log(f"   [SIP] ❌ Ошибка скачивания: {r.status_code} (Проверь права на сервере)")
            
    except Exception as e:
        log(f"   [SIP] Fail: {e}")

def test_ftp_cycle():
    log(f"=== FTP TEST ===")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21)
        ftp.login("dlpuser", "dlpsecret")
        local_file = "ftp_leak.txt"
        with open(local_file, "w") as f: f.write(f"CONFIDENTIAL: {SECRET}")
        with open(local_file, "rb") as f: ftp.storbinary(f"STOR {local_file}", f)
        
        with open(os.path.join(RESULTS_DIR, "ftp_evidence.txt"), "wb") as f: 
            ftp.retrbinary(f"RETR {local_file}", f.write)
        ftp.quit()
        os.remove(local_file)
        log("   [FTP] ✅ OK")
    except Exception as e: log(f"   [FTP] Fail: {e}")

def test_h323_replay():
    if not HAS_SCAPY: return
    log("=== H.323 REPLAY ===")
    pcap_path = "pcaps/h323.pcap"
    if not os.path.exists(pcap_path):
        log("   [SKIP] Файл pcaps/h323.pcap не найден.")
        return
    try:
        packets = rdpcap(pcap_path)
        log(f"   [H.323] Отправка {len(packets)} пакетов...")
        for pkt in packets:
            if IP in pkt: 
                pkt[IP].dst = HOST
                del pkt[IP].chksum # Scapy пересчитает
            sendp(pkt, verbose=0)
            time.sleep(0.002)
        log("   [H.323] ✅ OK")
    except Exception as e:
        log(f"   [H.323] Fail: {e}")

def test_browser():
    log("=== BROWSER TEST ===")
    opts = Options()
    opts.add_argument("--ignore-certificate-errors")
    # opts.add_argument("--headless") # Раскомментируй, если не хочешь видеть окно
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    driver.set_page_load_timeout(15)

    urls = [
        ("Google Search", f"https://www.google.com/search?q={SECRET}"),
        ("WhatsApp", "https://web.whatsapp.com"),
        ("Telegram", "https://web.telegram.org"),
        ("Skype", "https://web.skype.com"),
        ("Http Site", "http://example.com")
    ]
    
    for name, link in urls:
        try:
            log(f"   [WEB] {name}...")
            driver.get(link)
            time.sleep(3)
        except: log(f"   [WEB] Skip {name}")
        
    driver.quit()
    log("   [WEB] ✅ Done.")

def test_others():
    log("=== OTHERS ===")
    # Radius
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'\x01'*20, (HOST, 1812))
        log("   [RADIUS] ✅ Packet sent.")
    except: pass
    
    # Telnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2); s.connect((HOST, 23))
        s.recv(1024); s.send(b"exit\n"); s.close()
        log("   [TELNET] ✅ Connection OK.")
    except Exception as e: log(f"   [TELNET] Fail: {e}")

# ===========================
# MAIN
# ===========================
if __name__ == "__main__":
    print(f"Target Server: {HOST}")
    if HOST.endswith(".X"):
        print("❌ ОШИБКА: Замени IP в config.py!")
        exit()

    # Запуск сниффера
    if HAS_SCAPY:
        sniff_thread = threading.Thread(target=traffic_sniffer)
        sniff_thread.start()
        time.sleep(2)
        
    # Тесты
    test_ftp_cycle()
    test_email_cycle()
    test_xmpp_raw()   # <-- Добавили XMPP
    test_sip_voip()
    test_h323_replay()
    test_others()
    test_browser()
    
    # Стоп сниффера
    log("🏁 Завершение...")
    if HAS_SCAPY:
        stop_sniffer.set()
        sniff_thread.join()
        
    print(f"\n📂 Результаты: {os.path.abspath(RESULTS_DIR)}")