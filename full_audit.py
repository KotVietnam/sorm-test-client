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
    from scapy.all import sniff, wrpcap, rdpcap, sendp, IP, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] Scapy не установлен. PCAP логи работать не будут.")

# --- CONFIG ---
HOST = config.LAB_SERVER_IP
SECRET = config.SECRET_DATA
RESULTS_DIR = "test_results"

if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

def log(msg): print(f"[AUDIT] {msg}")

# ===========================
# 1. СНИФФЕР (С ФИЛЬТРОМ)
# ===========================
stop_sniffer = threading.Event()

def traffic_sniffer():
    if not HAS_SCAPY: return
    pcap_file = os.path.join(RESULTS_DIR, "session_dump.pcap")
    
    # ФИЛЬТР: Записываем ТОЛЬКО трафик, связанный с нашим сервером.
    # Это уберет лишний шум.
    bpf_filter = f"host {HOST}"
    
    log(f"🔴 [SNIFFER] Запись трафика в {pcap_file}")
    log(f"   [FILTER] Ловим только: {bpf_filter}")
    
    try:
        # sniff будет ловить только пакеты, где src или dst == HOST
        packets = sniff(filter=bpf_filter, stop_filter=lambda x: stop_sniffer.is_set(), timeout=None)
        wrpcap(pcap_file, packets)
        log(f"✅ [SNIFFER] Лог сохранен ({len(packets)} пакетов).")
    except Exception as e:
        log(f"❌ [SNIFFER] Ошибка: {e}. Возможно, не установлен Npcap?")

# ===========================
# 2. БРАУЗЕР (ПОЛНАЯ ВЕРСИЯ)
# ===========================
def test_browser():
    log("=== BROWSER TEST (Full List) ===")
    opts = Options()
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--start-maximized") # Чтобы видеть процесс
    # opts.add_argument("--headless")    # Раскомментируй, чтобы скрыть окно

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    driver.set_page_load_timeout(10)

    # 1. HTTP Сайты
    http_sites = [
        "http://kremlin.ru", 
        "http://neverssl.com",
        "http://example.com"
    ]
    log("   [WEB] 1. Проверка HTTP сайтов...")
    for url in http_sites:
        try:
            driver.get(url)
            log(f"      -> {url} : OK")
            time.sleep(2)
        except TimeoutException:
            log(f"      -> {url} : SKIP (Timeout)")
            driver.execute_script("window.stop();")
        except Exception as e:
            log(f"      -> {url} : ERR ({e})")

    # 2. Мессенджеры
    messengers = [
        ("WhatsApp Web", "https://web.whatsapp.com"),
        ("Telegram Web", "https://web.telegram.org"),
        ("Skype Web", "https://web.skype.com")
    ]
    log("   [WEB] 2. Проверка мессенджеров...")
    for name, url in messengers:
        try:
            driver.get(url)
            log(f"      -> {name} : Открыт")
            time.sleep(3)
        except TimeoutException:
            log(f"      -> {name} : SKIP (Timeout)")
            driver.execute_script("window.stop();")

    # 3. Google Поиск
    log(f"   [WEB] 3. Поиск Google: '{SECRET}'")
    try:
        driver.get(f"https://www.google.com/search?q={SECRET}")
        time.sleep(2)
    except: pass

    driver.quit()
    log("   [WEB] ✅ Браузер отработал.")

# ===========================
# 3. СЕТЕВЫЕ ТЕСТЫ
# ===========================

def test_sip_voip():
    log(f"=== SIP/VoIP TEST (Call -> Record -> Download) ===")
    try:
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
        time.sleep(5) # Ждем пока Asterisk отработает скрипт chmod
        
        # Скачивание
        url = f"http://{HOST}/recordings/dlp_record.wav"
        save_path = os.path.join(RESULTS_DIR, "call_evidence.wav")
        
        log(f"   [SIP] Попытка скачать: {url}")
        r = requests.get(url)
        if r.status_code == 200:
            with open(save_path, 'wb') as f: f.write(r.content)
            log(f"   [SIP] ✅ УСПЕХ: Файл скачан ({len(r.content)} байт).")
        else:
            log(f"   [SIP] ❌ Ошибка скачивания: Код {r.status_code} (Проверь chmod в extensions.conf)")
            
    except Exception as e:
        log(f"   [SIP] Fail: {e}")

def test_ftp_cycle():
    log(f"=== FTP TEST ===")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21)
        ftp.login("dlpuser", "dlpsecret")
        local_file = "secret_ftp.txt"
        with open(local_file, "w") as f: f.write(f"CONFIDENTIAL: {SECRET}")
        with open(local_file, "rb") as f: ftp.storbinary(f"STOR {local_file}", f)
        
        verified = os.path.join(RESULTS_DIR, "ftp_evidence.txt")
        with open(verified, "wb") as f: ftp.retrbinary(f"RETR {local_file}", f.write)
        ftp.quit()
        os.remove(local_file)
        log("   [FTP] ✅ Загрузка и скачивание успешны.")
    except Exception as e: log(f"   [FTP] Fail: {e}")

def test_email_cycle():
    log(f"=== EMAIL TEST ===")
    try:
        s = smtplib.SMTP(HOST, 25)
        s.login("u", "p")
        s.sendmail("a@l", "u@l", f"Subject: LEAK\n\n{SECRET}".encode())
        s.quit()
        time.sleep(1)
        p = poplib.POP3(HOST, 110)
        p.user("user"); p.pass_("pass")
        if len(p.list()[1]) > 0:
            with open(os.path.join(RESULTS_DIR, "email.eml"), "wb") as f:
                f.write(b"\n".join(p.retr(len(p.list()[1]))[1]))
            log("   [POP3] ✅ Письмо получено.")
        p.quit()
    except Exception as e: log(f"   [EMAIL] Fail: {e}")

def test_h323_replay():
    if not HAS_SCAPY: return
    log("=== H.323 REPLAY TEST ===")
    pcap_path = "pcaps/h323.pcap"
    if not os.path.exists(pcap_path):
        log("   [SKIP] Файл pcaps/h323.pcap не найден. Скачайте пример H.323 трафика в эту папку.")
        return
    try:
        packets = rdpcap(pcap_path)
        log(f"   [H.323] Отправка {len(packets)} пакетов на {HOST}...")
        for pkt in packets:
            if IP in pkt: 
                pkt[IP].dst = HOST
                # Убираем checksum, Scapy пересчитает
                del pkt[IP].chksum
            sendp(pkt, verbose=0)
            time.sleep(0.002)
        log("   [H.323] ✅ Трафик отправлен.")
    except Exception as e:
        log(f"   [H.323] Fail: {e}")

def test_others():
    log("=== OTHERS ===")
    # Radius
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'\x01'*20, (HOST, 1812))
        log("   [RADIUS] ✅ OK")
    except: pass
    # Telnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2); s.connect((HOST, 23))
        s.recv(1024); s.send(b"exit\n"); s.close()
        log("   [TELNET] ✅ OK")
    except Exception as e: log(f"   [TELNET] Fail: {e}")

# ===========================
# MAIN
# ===========================
if __name__ == "__main__":
    print(f"Target Server: {HOST}")
    if HOST.endswith(".X"):
        print("❌ ОШИБКА: Замени IP в config.py!")
        exit()

    # 1. Запуск сниффера
    if HAS_SCAPY:
        sniff_thread = threading.Thread(target=traffic_sniffer)
        sniff_thread.start()
        time.sleep(2)
        
    # 2. Тесты
    test_ftp_cycle()
    test_email_cycle()
    test_sip_voip()
    test_h323_replay()
    test_others()
    test_browser()
    
    # 3. Стоп сниффер
    log("🏁 Завершение...")
    if HAS_SCAPY:
        stop_sniffer.set()
        try: # Пингуем сами себя, чтобы разбудить сниффер
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'', ("127.0.0.1", 65432))
        except: pass
        sniff_thread.join()
        
    print(f"\n📂 Результаты: {os.path.abspath(RESULTS_DIR)}")