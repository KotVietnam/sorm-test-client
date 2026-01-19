#!/usr/bin/env python3
import argparse
import io
import os
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid

import ftplib
import imaplib
import poplib
import smtplib
import telnetlib

try:
    import requests
except Exception as exc:  # pragma: no cover - dependency availability
    requests = None
    REQUESTS_IMPORT_ERROR = exc
else:
    REQUESTS_IMPORT_ERROR = None
    try:
        import urllib3
    except Exception:
        urllib3 = None
    else:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from scapy.all import IP, TCP, UDP, Raw, conf, send
except Exception as exc:  # pragma: no cover - dependency availability
    IP = TCP = UDP = Raw = conf = send = None
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None
    conf.verb = 0

try:
    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    from pyrad.packet import AccessRequest
except Exception as exc:  # pragma: no cover - dependency availability
    Client = Dictionary = AccessRequest = None
    PYRAD_IMPORT_ERROR = exc
else:
    PYRAD_IMPORT_ERROR = None


class TrafficBlaster:
    COLOR_OK = "\033[32m"
    COLOR_FAIL = "\033[31m"
    COLOR_WARN = "\033[33m"
    COLOR_INFO = "\033[34m"
    COLOR_RESET = "\033[0m"

    def __init__(
        self,
        server_ip,
        timeout=5.0,
        domain="dlp.local",
        mail_user="dlp",
        mail_pass="dlp",
        mail_from=None,
        mail_to=None,
        ftp_user="dlp",
        ftp_pass="dlp",
        radius_secret="testing123",
        radius_user="dlpuser",
        radius_pass="dlppass",
        mgcp_endpoint="gw1",
        rss_path=None,
    ):
        self.server_ip = server_ip
        self.timeout = float(timeout)
        self.domain = domain
        self.mail_user = mail_user
        self.mail_pass = mail_pass
        self.mail_from = mail_from or f"{mail_user}@{domain}"
        self.mail_to = mail_to or f"{mail_user}@{domain}"
        self.ftp_user = ftp_user
        self.ftp_pass = ftp_pass
        self.radius_secret = radius_secret
        self.radius_user = radius_user
        self.radius_pass = radius_pass
        self.mgcp_endpoint = mgcp_endpoint
        self.rss_path = rss_path or os.path.join(os.getcwd(), "data", "client", "rss.xml")
        self.local_ip = self._detect_local_ip()

    def _detect_local_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((self.server_ip, 9))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            sock.close()

    def _log(self, status, message, color):
        print(f"{color}[{status}]{self.COLOR_RESET} {message}")

    def _log_ok(self, message):
        self._log("OK", message, self.COLOR_OK)

    def _log_fail(self, message):
        self._log("FAIL", message, self.COLOR_FAIL)

    def _log_warn(self, message):
        self._log("WARN", message, self.COLOR_WARN)

    def _log_info(self, message):
        self._log("INFO", message, self.COLOR_INFO)

    def _scapy_send(self, packet, label):
        if send is None:
            self._log_fail(f"{label}: scapy unavailable ({SCAPY_IMPORT_ERROR})")
            return
        try:
            send(packet, verbose=0)
            self._log_ok(f"{label}: packet sent")
        except PermissionError as exc:
            self._log_fail(f"{label}: permission denied ({exc})")
        except Exception as exc:
            self._log_fail(f"{label}: send failed ({exc})")

    def sip_options(self, port=5060):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        target = self.server_ip
        try:
            sock.connect((self.server_ip, port))
            local_ip, local_port = sock.getsockname()
            branch = f"z9hG4bK{uuid.uuid4().hex}"
            call_id = uuid.uuid4().hex
            tag = random.randint(1000, 9999)
            msg = (
                f"OPTIONS sip:{target} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}\r\n"
                "Max-Forwards: 70\r\n"
                f"To: <sip:{target}>\r\n"
                f"From: <sip:traffic@{self.domain}>;tag={tag}\r\n"
                f"Call-ID: {call_id}\r\n"
                "CSeq: 1 OPTIONS\r\n"
                f"Contact: <sip:traffic@{local_ip}>\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.send(msg.encode("ascii", "ignore"))
            self._log_ok("SIP OPTIONS sent")
            try:
                sock.recv(4096)
                self._log_ok("SIP response received")
            except socket.timeout:
                self._log_warn("SIP response timeout")
        except Exception as exc:
            self._log_fail(f"SIP OPTIONS failed ({exc})")
        finally:
            sock.close()

    def h323_call(self):
        tool = shutil.which("yate-console") or shutil.which("simph323")
        if not tool:
            self._log_warn("H.323 tool not found (yate-console/simph323)")
            return
        try:
            if os.path.basename(tool) == "yate-console":
                cmd = [tool, "-t"]
                input_data = f"callto h323/{self.server_ip}\nquit\n"
            else:
                cmd = [tool, self.server_ip]
                input_data = None
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            if result.returncode == 0:
                self._log_ok(f"H.323 tool executed ({os.path.basename(tool)})")
            else:
                self._log_warn(
                    f"H.323 tool error ({os.path.basename(tool)} rc={result.returncode})"
                )
        except subprocess.TimeoutExpired:
            self._log_warn("H.323 tool timeout")
        except Exception as exc:
            self._log_fail(f"H.323 tool failed ({exc})")

    def iax2_ping(self, port=4569):
        if send is None:
            self._log_fail(f"IAX2 ping: scapy unavailable ({SCAPY_IMPORT_ERROR})")
            return
        src_call = random.randint(1, 0x7FFF)
        dst_call = 0
        timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        oseq = 0
        iseq = 0
        frame_type = 0x06
        subclass = 0x02
        payload = struct.pack(
            "!HHI4B",
            0x8000 | src_call,
            dst_call,
            timestamp,
            oseq,
            iseq,
            frame_type,
            subclass,
        )
        packet = (
            IP(dst=self.server_ip)
            / UDP(sport=random.randint(1024, 65535), dport=port)
            / Raw(load=payload)
        )
        self._scapy_send(packet, "IAX2 ping")

    def mgcp_auep(self, port=2427):
        if send is None:
            self._log_fail(f"MGCP AUEP: scapy unavailable ({SCAPY_IMPORT_ERROR})")
            return
        msg = f"AUEP 1234 {self.mgcp_endpoint} MGCP 1.0\r\n\r\n"
        packet = (
            IP(dst=self.server_ip)
            / UDP(sport=random.randint(1024, 65535), dport=port)
            / Raw(load=msg.encode("ascii"))
        )
        self._scapy_send(packet, "MGCP AUEP")

    def skinny_keepalive(self, port=2000):
        if send is None:
            self._log_fail(f"Skinny keepalive: scapy unavailable ({SCAPY_IMPORT_ERROR})")
            return
        payload = struct.pack("<II", 4, 0x00000000)
        packet = (
            IP(dst=self.server_ip)
            / TCP(sport=random.randint(1024, 65535), dport=port, flags="PA")
            / Raw(load=payload)
        )
        self._scapy_send(packet, "Skinny keepalive")

    def smtp_send(self, port=25):
        try:
            with smtplib.SMTP(self.server_ip, port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                msg = (
                    f"From: {self.mail_from}\r\n"
                    f"To: {self.mail_to}\r\n"
                    "Subject: CONFIDENTIAL\r\n\r\n"
                    "DLP test message."
                )
                smtp.sendmail(self.mail_from, [self.mail_to], msg)
            self._log_ok("SMTP mail sent")
        except Exception as exc:
            self._log_fail(f"SMTP failed ({exc})")

    def pop3_check(self, port=110):
        try:
            pop = poplib.POP3(self.server_ip, port, timeout=self.timeout)
            pop.user(self.mail_user)
            pop.pass_(self.mail_pass)
            pop.noop()
            pop.quit()
            self._log_ok("POP3 mailbox checked")
        except Exception as exc:
            self._log_fail(f"POP3 failed ({exc})")

    def imap_check(self, port=143):
        try:
            imap = imaplib.IMAP4(self.server_ip, port)
            imap.login(self.mail_user, self.mail_pass)
            imap.select("INBOX")
            imap.logout()
            self._log_ok("IMAP mailbox checked")
        except Exception as exc:
            self._log_fail(f"IMAP failed ({exc})")

    def http_get(self):
        if requests is None:
            self._log_fail(f"HTTP GET: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        url = f"http://{self.server_ip}/"
        try:
            resp = requests.get(url, timeout=self.timeout)
            self._log_ok(f"HTTP GET {url} -> {resp.status_code}")
        except Exception as exc:
            self._log_fail(f"HTTP GET failed ({exc})")

    def https_get(self):
        if requests is None:
            self._log_fail(f"HTTPS GET: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        url = f"https://{self.server_ip}/"
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            self._log_ok(f"HTTPS GET {url} -> {resp.status_code}")
        except Exception as exc:
            self._log_fail(f"HTTPS GET failed ({exc})")

    def rss_download(self):
        if requests is None:
            self._log_fail(f"RSS download: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        url = f"http://{self.server_ip}/rss.xml"
        try:
            resp = requests.get(url, timeout=self.timeout)
            os.makedirs(os.path.dirname(self.rss_path), exist_ok=True)
            with open(self.rss_path, "wb") as handle:
                handle.write(resp.content)
            self._log_ok(f"RSS downloaded to {self.rss_path} ({resp.status_code})")
        except Exception as exc:
            self._log_fail(f"RSS download failed ({exc})")

    def ftp_transfer(self, port=21):
        data = f"dlp test {time.time()}\n".encode("ascii")
        ftp = ftplib.FTP()
        try:
            ftp.connect(self.server_ip, port, timeout=self.timeout)
            ftp.login(self.ftp_user, self.ftp_pass)
            ftp.set_pasv(True)
            ftp.storbinary("STOR dlp_test.txt", io.BytesIO(data))
            self._log_ok("FTP upload completed")
            downloaded = io.BytesIO()
            ftp.retrbinary("RETR dlp_test.txt", downloaded.write)
            self._log_ok("FTP download completed")
            ftp.quit()
        except Exception as exc:
            self._log_fail(f"FTP transfer failed ({exc})")
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def irc_hello(self, port=6667):
        try:
            with socket.create_connection((self.server_ip, port), timeout=self.timeout) as sock:
                nick = f"dlp{random.randint(1000, 9999)}"
                payload = f"NICK {nick}\r\nUSER {nick} 0 * :{nick}\r\n"
                sock.sendall(payload.encode("ascii"))
            self._log_ok("IRC NICK/USER sent")
        except Exception as exc:
            self._log_fail(f"IRC failed ({exc})")

    def xmpp_stream(self, port=5222):
        try:
            with socket.create_connection((self.server_ip, port), timeout=self.timeout) as sock:
                stream = (
                    "<?xml version='1.0'?>"
                    "<stream:stream to='{domain}' "
                    "version='1.0' "
                    "xmlns='jabber:client' "
                    "xmlns:stream='http://etherx.jabber.org/streams'>"
                ).format(domain=self.domain)
                sock.sendall(stream.encode("ascii"))
            self._log_ok("XMPP stream started")
        except Exception as exc:
            self._log_fail(f"XMPP failed ({exc})")

    def radius_access_request(self, port=1812):
        if Client is None:
            self._log_fail(f"RADIUS: pyrad unavailable ({PYRAD_IMPORT_ERROR})")
            return
        dict_file = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as handle:
                dict_file = handle.name
                handle.write("ATTRIBUTE User-Name 1 string\n")
                handle.write("ATTRIBUTE User-Password 2 string\n")
                handle.write("ATTRIBUTE NAS-IP-Address 4 ipaddr\n")
            dictionary = Dictionary(dict_file)
            client = Client(server=self.server_ip, secret=self.radius_secret.encode("ascii"), dict=dictionary)
            client.timeout = self.timeout
            client.retries = 1
            req = client.CreateAuthPacket(code=AccessRequest)
            req["User-Name"] = self.radius_user
            req["User-Password"] = req.PwCrypt(self.radius_pass)
            req["NAS-IP-Address"] = self.local_ip
            client.SendPacket(req)
            self._log_ok("RADIUS Access-Request sent")
        except Exception as exc:
            self._log_fail(f"RADIUS failed ({exc})")
        finally:
            if dict_file and os.path.exists(dict_file):
                os.unlink(dict_file)

    def telnet_session(self, port=23):
        try:
            with telnetlib.Telnet(self.server_ip, port, timeout=self.timeout) as tn:
                tn.write(b"\r\n")
                tn.write(b"exit\r\n")
            self._log_ok("Telnet session opened/closed")
        except Exception as exc:
            self._log_fail(f"Telnet failed ({exc})")

    def blast_all(self):
        self._log_info(f"Target: {self.server_ip} (local {self.local_ip})")
        self.sip_options()
        self.h323_call()
        self.iax2_ping()
        self.mgcp_auep()
        self.skinny_keepalive()
        self.smtp_send()
        self.pop3_check()
        self.imap_check()
        self.http_get()
        self.https_get()
        self.rss_download()
        self.ftp_transfer()
        self.irc_hello()
        self.xmpp_stream()
        self.radius_access_request()
        self.telnet_session()


def parse_args():
    parser = argparse.ArgumentParser(description="DLP-Test-Lab traffic generator")
    parser.add_argument("server_ip", help="DLP-Test-Lab server IP address")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    parser.add_argument("--domain", default=os.getenv("DLP_DOMAIN", "dlp.local"))
    parser.add_argument("--mail-user", default=os.getenv("DLP_MAIL_USER", "dlp"))
    parser.add_argument("--mail-pass", default=os.getenv("DLP_MAIL_PASS", "dlp"))
    parser.add_argument("--mail-from", default=os.getenv("DLP_MAIL_FROM"))
    parser.add_argument("--mail-to", default=os.getenv("DLP_MAIL_TO"))
    parser.add_argument("--ftp-user", default=os.getenv("DLP_FTP_USER", "dlp"))
    parser.add_argument("--ftp-pass", default=os.getenv("DLP_FTP_PASS", "dlp"))
    parser.add_argument("--radius-secret", default=os.getenv("DLP_RADIUS_SECRET", "testing123"))
    parser.add_argument("--radius-user", default=os.getenv("DLP_RADIUS_USER", "dlpuser"))
    parser.add_argument("--radius-pass", default=os.getenv("DLP_RADIUS_PASS", "dlppass"))
    parser.add_argument("--mgcp-endpoint", default=os.getenv("DLP_MGCP_ENDPOINT", "gw1"))
    parser.add_argument("--rss-path", default=os.getenv("DLP_RSS_PATH"))
    return parser.parse_args()


def main():
    args = parse_args()
    blaster = TrafficBlaster(
        args.server_ip,
        timeout=args.timeout,
        domain=args.domain,
        mail_user=args.mail_user,
        mail_pass=args.mail_pass,
        mail_from=args.mail_from,
        mail_to=args.mail_to,
        ftp_user=args.ftp_user,
        ftp_pass=args.ftp_pass,
        radius_secret=args.radius_secret,
        radius_user=args.radius_user,
        radius_pass=args.radius_pass,
        mgcp_endpoint=args.mgcp_endpoint,
        rss_path=args.rss_path,
    )
    blaster.blast_all()


if __name__ == "__main__":
    main()
