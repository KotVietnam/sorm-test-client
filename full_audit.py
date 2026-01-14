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

# Попытка импорта Scapy для сниффера и H.323
try:
    from scapy.all import sniff, wrpcap, rdpcap, sendp, IP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] Scapy не установлен. PCAP логи и H.323 не будут работать.")

# --- CONFIG ---
HOST = config.LAB_SERVER_IP
SECRET = config.SECRET_DATA
RESULTS_DIR = "test_results"

# Создаем папку результатов
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

def log(msg): print(f"[AUDIT] {msg}")

# ===========================
# 1. ФОНОВЫЙ СНИФФЕР
# ===========================
stop_sniffer = threading.Event()

def traffic_sniffer():
    if not HAS_SCAPY: return
    pcap_file = os.path.join(RESULTS_DIR, "session_dump.pcap")
    log(f"🔴 [SNIFFER] Запись трафика в {pcap_file}...")
    try:
        packets = sniff(stop_filter=lambda x: stop_sniffer.is_set(), timeout=None)
        wrpcap(pcap_file, packets)
        log(f"✅ [SNIFFER] Лог сохранен ({len(packets)} пакетов).")
    except Exception as e:
        log(f"❌ [SNIFFER] Ошибка: {e}")

# ===========================
# 2. СЕТЕВЫЕ ТЕСТЫ (LOOPBACK)
# ===========================

def test_ftp_cycle():
    log(f"=== FTP TEST (Upload -> Download Check) ===")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21)
        ftp.login("dlpuser", "dlpsecret")
        
        # Создаем и грузим файл
        local_file = "secret_ftp.txt"
        with open(local_file, "w") as f: f.write(f"CONFIDENTIAL FTP DATA: {SECRET}")
        
        log("   [FTP] ⬆️ Загрузка файла...")
        with open(local_file, "rb") as f: ftp.storbinary(f"STOR {local_file}", f)
        
        # Скачиваем обратно для проверки
        verified_file = os.path.join(RESULTS_DIR, "ftp_evidence.txt")
        log("   [FTP] ⬇️ Скачивание обратно...")
        with open(verified_file, "wb") as f: ftp.retrbinary(f"RETR {local_file}", f.write)
        
        # Сверяем
        with open(verified_file, "r") as f: 
            if SECRET in f.read(): log("   [FTP] ✅ УСПЕХ: Файл перехвачен корректно.")
            else: log("   [FTP] ⚠️ Файл скачан, но содержимое отличается.")
            
        ftp.quit()
        os.remove(local_file)
    except Exception as e:
        log(f"   [FTP] Fail: {e}")

def test_email_cycle():
    log(f"=== EMAIL TEST (SMTP -> POP3 Check) ===")
    # 1. Отправка
    try:
        server = smtplib.SMTP(HOST, 25)
        server.login("user", "pass")
        msg = f"Subject: AUDIT LEAK\n\nSecret: {SECRET}"
        server.sendmail("audit@local", "user@local", msg.encode('utf-8'))
        server.quit()
        log("   [SMTP] ⬆️ Письмо отправлено.")
    except Exception as e:
        log(f"   [SMTP] Fail: {e}")
        return

    time.sleep(2)

    # 2. Скачивание (POP3)
    try:
        pop = poplib.POP3(HOST, 110)
        pop.user("user")
        pop.pass_("pass")
        num = len(pop.list()[1])
        if num > 0:
            resp, lines, octets = pop.retr(num)
            full_msg = b"\n".join(lines).decode('utf-8')
            evidence_path = os.path.join(RESULTS_DIR, "email_evidence.eml")
            with open(evidence_path, "w") as f: f.write(full_msg)
            
            if SECRET in full_msg: log("   [POP3] ✅ УСПЕХ: Письмо с секретом получено.")
            else: log("   [POP3] ⚠️ Письмо получено без секрета.")
        else:
            log("   [POP3] ❌ Ящик пуст.")
        pop.quit()
    except Exception as e:
        log(f"   [POP3] Fail: {e}")

def test_sip_voip():
    log(f"=== SIP/VoIP TEST (Call -> Record -> Download) ===")
    try:
        # 1. Звонок
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        invite = f"INVITE sip:100@{HOST} SIP/2.0\r\nCall-ID: {int(time.time())}\r\nFrom: auditor\r\n".encode()
        sock.sendto(invite, (HOST, 5060))
        
        log("   [SIP] 📞 Звонок и генерация RTP (10 сек)...")
        # RTP Шум
        for i in range(500):
            sock.sendto(os.urandom(160), (HOST, 10000))
            time.sleep(0.02)
        sock.close()
        log("   [SIP] 🏁 Звонок завершен. Ждем сохранения wav...")
        time.sleep(5)
        
        # 2. Скачивание записи
        url = f"http://{HOST}/recordings/dlp_record.wav"
        save_path = os.path.join(RESULTS_DIR, "call_evidence.wav")
        r = requests.get(url)
        if r.status_code == 200:
            with open(save_path, 'wb') as f: f.write(r.content)
            log(f"   [SIP] ✅ УСПЕХ: Запись разговора скачана ({len(r.content)} байт).")
        else:
            log(f"   [SIP] ❌ Ошибка скачивания записи: {r.status_code}")
            
    except Exception as e:
        log(f"   [SIP] Fail: {e}")

def test_h323_replay():
    if not HAS_SCAPY: return
    log("=== H.323 REPLAY TEST ===")
    pcap_path = "pcaps/h323.pcap"
    if not os.path.exists(pcap_path):
        log("   [SKIP] Файл pcaps/h323.pcap не найден.")
        return
    try:
        packets = rdpcap(pcap_path)
        log(f"   [H.323] Отправка {len(packets)} пакетов...")
        for pkt in packets:
            if IP in pkt: pkt[IP].dst = HOST
            sendp(pkt, verbose=0)
            time.sleep(0.005)
        log("   [H.323] ✅ Трафик отправлен.")
    except Exception as e:
        log(f"   [H.323] Fail: {e}")

def test_browser():
    log("=== BROWSER TEST ===")
    opts = Options()
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--headless") 
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
        driver.set_page_load_timeout(15)
        
        target = f"https://www.google.com/search?q={SECRET}"
        log(f"   [WEB] Запрос: {target}")
        try: driver.get(target)
        except: pass
        
        driver.quit()
        log("   [WEB] ✅ Браузер отработал.")
    except Exception as e:
        log(f"   [WEB] Fail: {e}")

def test_others():
    log("=== OTHERS (Telnet/Radius) ===")
    # Radius
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'\x01\x01\x00\x14' + b'\x00'*16, (HOST, 1812))
        log("   [RADIUS] ✅ Пакет отправлен.")
    except: pass
    
    # Telnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((HOST, 23))
        # Ждем баннер Busybox
        s.recv(1024) 
        s.send(b"exit\n")
        s.close()
        log("   [TELNET] ✅ Подключение успешно.")
    except Exception as e:
        log(f"   [TELNET] Fail: {e}")

# ===========================
# MAIN
# ===========================
if __name__ == "__main__":
    print(f"Target Server: {HOST}")
    
    # 1. Start Sniffer
    if HAS_SCAPY:
        sniff_thread = threading.Thread(target=traffic_sniffer)
        sniff_thread.start()
        time.sleep(2)
        
    # 2. Run Tests
    test_ftp_cycle()
    test_email_cycle()
    test_sip_voip()
    test_h323_replay()
    test_others()
    test_browser()
    
    # 3. Stop Sniffer
    log("🏁 Остановка сниффера...")
    if HAS_SCAPY:
        stop_sniffer.set()
        # Wake up sniffer packet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'', ("127.0.0.1", 55555))
        except: pass
        sniff_thread.join()
        
    print(f"\n📂 Результаты в папке: {os.path.abspath(RESULTS_DIR)}")