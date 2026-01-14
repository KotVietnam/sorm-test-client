import ftplib
import smtplib
import poplib
import imaplib
import nntplib
import socket
import os
import time
import threading
import json

# --- Imports для Браузера ---
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

import config

# --- Imports для XMPP ---
try:
    import slixmpp
    HAS_XMPP = True
except ImportError:
    HAS_XMPP = False
    print("[WARN] Библиотека slixmpp не найдена. XMPP тест будет пропущен.")

HOST = config.LAB_SERVER_IP
SECRET = config.SECRET_DATA

def log(msg): print(f"[FULL-AUDIT] {msg}")

# ==========================================
# ЧАСТЬ 1: БРАУЗЕР (Имитация пользователя)
# ==========================================
def test_browser_activity():
    log("=== ЗАПУСК БРАУЗЕРНЫХ ТЕСТОВ (Client Side) ===")
    
    opts = Options()
    opts.add_argument("--start-maximized")
    opts.add_argument("--ignore-certificate-errors")
    # opts.add_argument("--headless") # Раскомментируй, если не хочешь видеть окно
    
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
        driver.set_page_load_timeout(15) # Таймаут 15 сек на сайт
        
        # 1. HTTP Сайты
        http_sites = [
            "http://kremlin.ru", 
            "http://neverssl.com",
            "http://example.com"
        ]
        log("   [Browser] 1. Посещение HTTP сайтов...")
        for url in http_sites:
            try:
                driver.get(url)
                time.sleep(2)
                log(f"      -> {url} : OK")
            except TimeoutException:
                log(f"      -> {url} : SKIP (Timeout)")
                driver.execute_script("window.stop();")
            except Exception as e:
                log(f"      -> {url} : ERR ({e})")

        # 2. Поиск (HTTPS)
        log(f"   [Browser] 2. Поиск в Google: '{SECRET}'")
        try:
            driver.get(f"https://www.google.com/search?q={SECRET}")
            time.sleep(3)
        except: pass

        # 3. Мессенджеры
        messengers = [
            ("WhatsApp", "https://web.whatsapp.com"),
            ("Telegram", "https://web.telegram.org"),
        ]
        log("   [Browser] 3. Проверка мессенджеров...")
        for name, url in messengers:
            try:
                driver.get(url)
                time.sleep(4)
                log(f"      -> {name} : OK")
            except TimeoutException:
                log(f"      -> {name} : SKIP (Timeout)")
                driver.execute_script("window.stop();")

        # 4. HTTP POST утечка
        log("   [Browser] 4. Отправка данных через HTTP POST...")
        try:
            js_code = f"""
            fetch('https://httpbin.org/post', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{ secret_leak: '{SECRET}' }})
            }});
            """
            driver.execute_script(js_code)
            time.sleep(2)
            log("      -> POST запрос отправлен")
        except Exception as e:
            log(f"      -> Ошибка POST: {e}")

        driver.quit()
        log("   [Browser] Тесты завершены.")

    except Exception as e:
        log(f"[Browser] Критическая ошибка Selenium: {e}")

# ==========================================
# ЧАСТЬ 2: ИНФРАСТРУКТУРА (Server Side)
# ==========================================

def test_email_cycle():
    log(f"=== EMAIL CYCLE (SMTP -> IMAP -> POP3) ===")
    
    # A. SMTP (Отправка)
    try:
        server = smtplib.SMTP(HOST, 25)
        server.login("user", "pass")
        msg = f"Subject: FULL AUDIT LEAK\n\nSecret data: {SECRET}"
        server.sendmail("audit@local", "user@local", msg.encode('utf-8'))
        server.quit()
        log("   [SMTP] Письмо отправлено.")
    except Exception as e:
        log(f"   [SMTP] Fail: {e}")
        return

    time.sleep(2) # Ждем пока письмо упадет в ящик

    # B. IMAP (Чтение)
    try:
        mail = imaplib.IMAP4(HOST, 143)
        mail.login("user", "pass")
        mail.select("inbox")
        status, messages = mail.search(None, 'ALL')
        cnt = len(messages[0].split()) if messages[0] else 0
        log(f"   [IMAP] Найдено писем в ящике: {cnt}")
        mail.close()
        mail.logout()
    except Exception as e:
        log(f"   [IMAP] Fail: {e}")

    # C. POP3 (Скачивание)
    try:
        pop = poplib.POP3(HOST, 110)
        pop.user("user")
        pop.pass_("pass")
        if len(pop.list()[1]) > 0:
            pop.retr(1)
            log(f"   [POP3] Письмо успешно скачано.")
        pop.quit()
    except Exception as e:
        log(f"   [POP3] Fail: {e}")

def test_xmpp():
    if not HAS_XMPP: return
    log(f"=== XMPP (JABBER) ===")

    class EchoBot(slixmpp.ClientXMPP):
        def __init__(self, jid, password):
            slixmpp.ClientXMPP.__init__(self, jid, password)
            self.add_event_handler("session_start", self.start)
        def start(self, event):
            self.send_presence()
            self.get_roster()
            self.send_message(mto=self.boundjid.bare, mbody=f"Chat leak: {SECRET}", mtype='chat')
            self.disconnect(wait=True)

    try:
        xmpp = EchoBot(f"admin@{HOST}", "password")
        xmpp.connect((HOST, 5222), use_tls=False, use_ssl=False)
        process = threading.Thread(target=xmpp.process, kwargs={'timeout': 5})
        process.start()
        time.sleep(3)
        xmpp.disconnect()
        log("   [XMPP] Сессия и сообщение отправлены.")
    except Exception as e:
        log(f"   [XMPP] Fail: {e}")

def test_nntp():
    log(f"=== NNTP (NEWS) ===")
    try:
        s = nntplib.NNTP(HOST, 119)
        log(f"   [NNTP] Connected: {s.getwelcome()}")
        try: s.post(f"From: audit\r\nSubject: Leak\r\n\r\n{SECRET}")
        except: pass
        s.quit()
    except Exception as e:
        log(f"   [NNTP] Fail: {e}")

def test_ftp():
    log(f"=== FTP ===")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21)
        ftp.login("dlpuser", "dlpsecret")
        fname = "full_audit_leak.txt"
        with open(fname, "w") as f: f.write(SECRET)
        with open(fname, "rb") as f: ftp.storbinary(f"STOR {fname}", f)
        ftp.quit()
        os.remove(fname)
        log("   [FTP] Файл загружен.")
    except Exception as e:
        log(f"   [FTP] Fail: {e}")

def test_sip_voip():
    log(f"=== SIP / VoIP ===")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        invite = f"INVITE sip:100@{HOST} SIP/2.0\r\nCall-ID: 9999\r\nFrom: auditor\r\n".encode()
        sock.sendto(invite, (HOST, 5060))
        # RTP Stream (Шум)
        for i in range(20):
            sock.sendto(os.urandom(160), (HOST, 10000))
            time.sleep(0.02)
        sock.close()
        log("   [SIP] Звонок и голос сгенерированы.")
    except Exception as e:
        log(f"   [SIP] Fail: {e}")

def test_radius():
    log(f"=== RADIUS ===")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = b'\x01\x01\x00\x14' + b'\x00'*16 
        sock.sendto(packet, (HOST, 1812))
        sock.close()
        log("   [RADIUS] Auth Packet отправлен.")
    except Exception as e:
         log(f"   [RADIUS] Fail: {e}")

def test_telnet():
    log(f"=== TELNET ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((HOST, 23))
        s.send(b"user\n")
        time.sleep(0.5)
        s.send(b"pass\n")
        s.close()
        log("   [TELNET] Вход выполнен.")
    except Exception as e:
        log(f"   [TELNET] Fail: {e}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print(f"Target Server: {HOST}")
    if HOST == "192.168.1.X":
        print("[!] ОШИБКА: Настрой IP в config.py")
    else:
        # 1. Сначала запускаем браузер (визуальная часть)
        test_browser_activity()
        
        print("\n" + "="*40 + "\n")
        
        # 2. Затем прогоняем сетевые протоколы
        test_email_cycle()
        test_xmpp()
        test_nntp()
        test_ftp()
        test_sip_voip()
        test_radius()
        test_telnet()
        
        print("\n[DONE] Полный аудит завершен.")