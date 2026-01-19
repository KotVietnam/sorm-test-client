#!/usr/bin/env python3
import argparse
import io
import os
import random
import shutil
import socket
import select
import struct
import subprocess
import tempfile
import time
import uuid
import webbrowser

import ftplib
import imaplib
import poplib
import smtplib
try:
    import telnetlib
except Exception as exc:  # pragma: no cover - dependency availability
    telnetlib = None
    TELNETLIB_IMPORT_ERROR = exc
else:
    TELNETLIB_IMPORT_ERROR = None

try:
    import colorama
except Exception:  # pragma: no cover - dependency availability
    colorama = None

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


def load_env(path):
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'").strip('"')
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        return


def env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def env_float(name, default):
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


class TrafficBlaster:
    COLOR_OK = "\033[32m"
    COLOR_FAIL = "\033[31m"
    COLOR_WARN = "\033[33m"
    COLOR_INFO = "\033[34m"
    COLOR_DIM = "\033[90m"
    COLOR_BOLD = "\033[1m"
    COLOR_RESET = "\033[0m"
    DEFAULT_PUBLIC_SITES = (
        "https://kremlin.ru/",
        "https://web.whatsapp.com/",
        "https://web.telegram.org/",
        "https://www.instagram.com/",
    )

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
        open_sites=False,
        sites=None,
        sip_port=5060,
        iax2_port=4569,
        mgcp_port=2427,
        skinny_port=2000,
        smtp_port=25,
        pop3_port=110,
        imap_port=143,
        http_port=80,
        https_port=443,
        ftp_port=21,
        irc_port=6667,
        xmpp_port=5222,
        radius_port=1812,
        telnet_port=23,
        smtp_starttls=False,
        smtp_auth=True,
        pop3_ssl=False,
        imap_ssl=False,
        ftp_passive=True,
        radius_raw=False,
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
        self.open_sites = open_sites
        self.sites = sites or list(self.DEFAULT_PUBLIC_SITES)
        self.sip_port = int(sip_port)
        self.iax2_port = int(iax2_port)
        self.mgcp_port = int(mgcp_port)
        self.skinny_port = int(skinny_port)
        self.smtp_port = int(smtp_port)
        self.pop3_port = int(pop3_port)
        self.imap_port = int(imap_port)
        self.http_port = int(http_port)
        self.https_port = int(https_port)
        self.ftp_port = int(ftp_port)
        self.irc_port = int(irc_port)
        self.xmpp_port = int(xmpp_port)
        self.radius_port = int(radius_port)
        self.telnet_port = int(telnet_port)
        self.smtp_starttls = bool(smtp_starttls)
        self.smtp_auth = bool(smtp_auth)
        self.pop3_ssl = bool(pop3_ssl)
        self.imap_ssl = bool(imap_ssl)
        self.ftp_passive = bool(ftp_passive)
        self.radius_raw = bool(radius_raw)
        self.use_color = self._init_color()
        self.stats = {"ok": 0, "warn": 0, "fail": 0, "info": 0}
        self.local_ip = self._detect_local_ip()

    def _init_color(self):
        if os.getenv("NO_COLOR"):
            return False
        if os.name == "nt":
            if colorama is None:
                return False
            colorama.just_fix_windows_console()
        return True

    def _detect_local_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((self.server_ip, 9))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            sock.close()

    def _color(self, color):
        return color if self.use_color else ""

    def _header(self):
        line = "=" * 62
        title = "DLP TRAFFIC BLASTER"
        target = f"Target: {self.server_ip}"
        local = f"Local : {self.local_ip}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        print(self._color(self.COLOR_BOLD) + line + self._color(self.COLOR_RESET))
        print(self._color(self.COLOR_BOLD) + f"{title:^62}" + self._color(self.COLOR_RESET))
        print(self._color(self.COLOR_BOLD) + line + self._color(self.COLOR_RESET))
        print(f"{target:<31}{local:<31}")
        print(f"{'Started: ' + now:<62}")
        print(line)

    def _section(self, title):
        bar = f"-- {title} " + "-" * max(0, 54 - len(title))
        print(self._color(self.COLOR_INFO) + bar + self._color(self.COLOR_RESET))

    def _log(self, status, message, color):
        tag = f"[{status:^5}]"
        stamp = time.strftime("%H:%M:%S")
        colored_tag = self._color(color) + tag + self._color(self.COLOR_RESET)
        print(f"{colored_tag} {stamp} | {message}")

    def _log_ok(self, message):
        self.stats["ok"] += 1
        self._log("OK", message, self.COLOR_OK)

    def _log_fail(self, message):
        self.stats["fail"] += 1
        self._log("FAIL", message, self.COLOR_FAIL)

    def _log_warn(self, message):
        self.stats["warn"] += 1
        self._log("WARN", message, self.COLOR_WARN)

    def _log_info(self, message):
        self.stats["info"] += 1
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

    def sip_options(self, port=None):
        port = port or self.sip_port
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

    def iax2_ping(self, port=None):
        port = port or self.iax2_port
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

    def mgcp_auep(self, port=None):
        port = port or self.mgcp_port
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

    def skinny_keepalive(self, port=None):
        port = port or self.skinny_port
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

    def smtp_send(self, port=None):
        port = port or self.smtp_port
        try:
            with smtplib.SMTP(self.server_ip, port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if self.smtp_starttls:
                    smtp.starttls()
                    smtp.ehlo()
                if self.smtp_auth and self.mail_user and self.mail_pass:
                    try:
                        smtp.login(self.mail_user, self.mail_pass)
                    except smtplib.SMTPException as exc:
                        self._log_warn(f"SMTP auth skipped ({exc})")
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

    def pop3_check(self, port=None):
        port = port or self.pop3_port
        try:
            pop_class = poplib.POP3_SSL if self.pop3_ssl else poplib.POP3
            pop = pop_class(self.server_ip, port, timeout=self.timeout)
            pop.user(self.mail_user)
            pop.pass_(self.mail_pass)
            pop.noop()
            pop.quit()
            self._log_ok("POP3 mailbox checked")
        except Exception as exc:
            self._log_fail(f"POP3 failed ({exc})")

    def imap_check(self, port=None):
        port = port or self.imap_port
        try:
            imap_class = imaplib.IMAP4_SSL if self.imap_ssl else imaplib.IMAP4
            imap = imap_class(self.server_ip, port)
            imap.login(self.mail_user, self.mail_pass)
            imap.select("INBOX")
            imap.logout()
            self._log_ok("IMAP mailbox checked")
        except Exception as exc:
            self._log_fail(f"IMAP failed ({exc})")

    def http_get(self, port=None):
        if requests is None:
            self._log_fail(f"HTTP GET: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        port = port or self.http_port
        if int(port) == 80:
            url = f"http://{self.server_ip}/"
        else:
            url = f"http://{self.server_ip}:{port}/"
        try:
            resp = requests.get(url, timeout=self.timeout)
            self._log_ok(f"HTTP GET {url} -> {resp.status_code}")
        except Exception as exc:
            self._log_fail(f"HTTP GET failed ({exc})")

    def https_get(self, port=None):
        if requests is None:
            self._log_fail(f"HTTPS GET: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        port = port or self.https_port
        if int(port) == 443:
            url = f"https://{self.server_ip}/"
        else:
            url = f"https://{self.server_ip}:{port}/"
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            self._log_ok(f"HTTPS GET {url} -> {resp.status_code}")
        except Exception as exc:
            self._log_fail(f"HTTPS GET failed ({exc})")

    def rss_download(self, port=None):
        if requests is None:
            self._log_fail(f"RSS download: requests unavailable ({REQUESTS_IMPORT_ERROR})")
            return
        port = port or self.http_port
        if int(port) == 80:
            url = f"http://{self.server_ip}/rss.xml"
        else:
            url = f"http://{self.server_ip}:{port}/rss.xml"
        try:
            resp = requests.get(url, timeout=self.timeout)
            os.makedirs(os.path.dirname(self.rss_path), exist_ok=True)
            with open(self.rss_path, "wb") as handle:
                handle.write(resp.content)
            self._log_ok(f"RSS downloaded to {self.rss_path} ({resp.status_code})")
        except Exception as exc:
            self._log_fail(f"RSS download failed ({exc})")

    def ftp_transfer(self, port=None):
        port = port or self.ftp_port
        data = f"dlp test {time.time()}\n".encode("ascii")
        ftp = ftplib.FTP()
        try:
            ftp.connect(self.server_ip, port, timeout=self.timeout)
            ftp.login(self.ftp_user, self.ftp_pass)
            ftp.set_pasv(self.ftp_passive)
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

    def irc_hello(self, port=None):
        port = port or self.irc_port
        try:
            with socket.create_connection((self.server_ip, port), timeout=self.timeout) as sock:
                nick = f"dlp{random.randint(1000, 9999)}"
                payload = f"NICK {nick}\r\nUSER {nick} 0 * :{nick}\r\n"
                sock.sendall(payload.encode("ascii"))
            self._log_ok("IRC NICK/USER sent")
        except Exception as exc:
            self._log_fail(f"IRC failed ({exc})")

    def xmpp_stream(self, port=None):
        port = port or self.xmpp_port
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

    def radius_access_request(self, port=None):
        port = port or self.radius_port
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
            use_raw = self.radius_raw or os.name == "nt" or not hasattr(select, "poll")
            if use_raw:
                self._log_warn("RADIUS raw mode; sending without response wait")
                self._radius_send_fallback(req, port)
                return
            try:
                client.SendPacket(req)
                self._log_ok("RADIUS Access-Request sent")
            except Exception as exc:
                if "poll" in str(exc):
                    self._log_warn("RADIUS fallback due to poll error")
                    self._radius_send_fallback(req, port)
                else:
                    raise
        except Exception as exc:
            self._log_fail(f"RADIUS failed ({exc})")
        finally:
            if dict_file and os.path.exists(dict_file):
                os.unlink(dict_file)

    def _radius_send_fallback(self, req, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            packet = None
            for method_name in ("RequestPacket", "Pack", "packet"):
                if hasattr(req, method_name):
                    method = getattr(req, method_name)
                    packet = method() if callable(method) else method
                    if packet:
                        break
            if packet is None:
                raise RuntimeError("Unable to pack RADIUS request")
            sock.sendto(packet, (self.server_ip, port))
            self._log_ok("RADIUS Access-Request sent (no response wait)")
        except Exception as exc:
            self._log_fail(f"RADIUS fallback failed ({exc})")
        finally:
            sock.close()

    def telnet_session(self, port=None):
        port = port or self.telnet_port
        if telnetlib is None:
            self._log_warn(
                f"telnetlib unavailable ({TELNETLIB_IMPORT_ERROR}); using raw socket"
            )
            try:
                with socket.create_connection((self.server_ip, port), timeout=self.timeout) as sock:
                    sock.sendall(b"\r\n")
                    sock.sendall(b"exit\r\n")
                self._log_ok("Telnet session opened/closed (raw socket)")
            except Exception as exc:
                self._log_fail(f"Telnet failed ({exc})")
            return
        try:
            with telnetlib.Telnet(self.server_ip, port, timeout=self.timeout) as tn:
                tn.write(b"\r\n")
                tn.write(b"exit\r\n")
            self._log_ok("Telnet session opened/closed")
        except Exception as exc:
            self._log_fail(f"Telnet failed ({exc})")

    def open_public_sites(self):
        for url in self.sites:
            normalized = self._normalize_url(url)
            try:
                opened = webbrowser.open_new_tab(normalized)
                if opened:
                    self._log_ok(f"Browser opened {normalized}")
                else:
                    self._log_warn(f"Browser refused {normalized}")
            except Exception as exc:
                self._log_fail(f"Browser open failed for {normalized} ({exc})")

    def _normalize_url(self, url):
        cleaned = url.strip()
        if "://" not in cleaned:
            return f"https://{cleaned}"
        return cleaned

    def _summary(self, started_at):
        elapsed = time.time() - started_at
        total = sum(self.stats.values())
        line = "-" * 62
        print(self._color(self.COLOR_DIM) + line + self._color(self.COLOR_RESET))
        print(
            f"Total: {total} | OK: {self.stats['ok']} | WARN: {self.stats['warn']} "
            f"| FAIL: {self.stats['fail']} | INFO: {self.stats['info']} | "
            f"Time: {elapsed:.1f}s"
        )
        print(line)

    def blast_all(self):
        started_at = time.time()
        self._header()
        self._section("VoIP")
        self.sip_options()
        self.h323_call()
        self.iax2_ping()
        self.mgcp_auep()
        self.skinny_keepalive()
        self._section("Mail")
        self.smtp_send()
        self.pop3_check()
        self.imap_check()
        self._section("Web")
        self.http_get()
        self.https_get()
        self.rss_download()
        if self.open_sites:
            self._section("Browser")
            self.open_public_sites()
        self._section("File Transfer")
        self.ftp_transfer()
        self._section("Chat")
        self.irc_hello()
        self.xmpp_stream()
        self._section("Misc")
        self.radius_access_request()
        self.telnet_session()
        self._summary(started_at)


def parse_args():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=os.getenv("DLP_ENV_FILE", ".env"))
    pre_args, _ = pre.parse_known_args()
    load_env(pre_args.env_file)

    parser = argparse.ArgumentParser(description="DLP-Test-Lab traffic generator", parents=[pre])
    parser.add_argument(
        "server_ip",
        nargs="?",
        default=os.getenv("DLP_SERVER_IP"),
        help="DLP-Test-Lab server IP address (or set DLP_SERVER_IP)",
    )
    parser.add_argument("--timeout", type=float, default=env_float("DLP_TIMEOUT", 5.0), help="Socket timeout in seconds")
    parser.add_argument("--domain", default=os.getenv("DLP_DOMAIN", "dlp.local"))
    parser.add_argument("--mail-user", default=os.getenv("DLP_MAIL_USER", "dlp"))
    parser.add_argument("--mail-pass", default=os.getenv("DLP_MAIL_PASS", "dlp"))
    parser.add_argument("--mail-from", default=os.getenv("DLP_MAIL_FROM"))
    parser.add_argument("--mail-to", default=os.getenv("DLP_MAIL_TO"))
    parser.add_argument("--smtp-port", type=int, default=env_int("DLP_SMTP_PORT", 25))
    parser.add_argument("--pop3-port", type=int, default=env_int("DLP_POP3_PORT", 110))
    parser.add_argument("--imap-port", type=int, default=env_int("DLP_IMAP_PORT", 143))
    parser.add_argument("--smtp-starttls", action="store_true", default=env_flag("DLP_SMTP_STARTTLS"))
    parser.add_argument("--smtp-no-auth", action="store_true", default=env_flag("DLP_SMTP_NO_AUTH"))
    parser.add_argument("--pop3-ssl", action="store_true", default=env_flag("DLP_POP3_SSL"))
    parser.add_argument("--imap-ssl", action="store_true", default=env_flag("DLP_IMAP_SSL"))
    parser.add_argument("--http-port", type=int, default=env_int("DLP_HTTP_PORT", 80))
    parser.add_argument("--https-port", type=int, default=env_int("DLP_HTTPS_PORT", 443))
    parser.add_argument("--ftp-user", default=os.getenv("DLP_FTP_USER", "dlp"))
    parser.add_argument("--ftp-pass", default=os.getenv("DLP_FTP_PASS", "dlp"))
    parser.add_argument("--ftp-port", type=int, default=env_int("DLP_FTP_PORT", 21))
    parser.add_argument("--ftp-active", action="store_true", default=env_flag("DLP_FTP_ACTIVE"))
    parser.add_argument("--radius-secret", default=os.getenv("DLP_RADIUS_SECRET", "testing123"))
    parser.add_argument("--radius-user", default=os.getenv("DLP_RADIUS_USER", "dlpuser"))
    parser.add_argument("--radius-pass", default=os.getenv("DLP_RADIUS_PASS", "dlppass"))
    parser.add_argument("--radius-port", type=int, default=env_int("DLP_RADIUS_PORT", 1812))
    parser.add_argument("--radius-raw", action="store_true", default=env_flag("DLP_RADIUS_RAW"))
    parser.add_argument("--sip-port", type=int, default=env_int("DLP_SIP_PORT", 5060))
    parser.add_argument("--iax2-port", type=int, default=env_int("DLP_IAX2_PORT", 4569))
    parser.add_argument("--mgcp-port", type=int, default=env_int("DLP_MGCP_PORT", 2427))
    parser.add_argument("--skinny-port", type=int, default=env_int("DLP_SKINNY_PORT", 2000))
    parser.add_argument("--irc-port", type=int, default=env_int("DLP_IRC_PORT", 6667))
    parser.add_argument("--xmpp-port", type=int, default=env_int("DLP_XMPP_PORT", 5222))
    parser.add_argument("--telnet-port", type=int, default=env_int("DLP_TELNET_PORT", 23))
    parser.add_argument("--mgcp-endpoint", default=os.getenv("DLP_MGCP_ENDPOINT", "gw1"))
    parser.add_argument("--rss-path", default=os.getenv("DLP_RSS_PATH"))
    parser.add_argument("--open-sites", action="store_true", help="Open default public sites")
    parser.add_argument("--sites", default=os.getenv("DLP_SITES"), help="Comma-separated URLs")
    args = parser.parse_args()
    if not args.server_ip:
        parser.error("server_ip is required (or set DLP_SERVER_IP)")
    return args


def main():
    args = parse_args()
    sites = [item.strip() for item in args.sites.split(",") if item.strip()] if args.sites else None
    smtp_auth = not args.smtp_no_auth
    ftp_passive = not args.ftp_active
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
        open_sites=args.open_sites or bool(sites),
        sites=sites,
        sip_port=args.sip_port,
        iax2_port=args.iax2_port,
        mgcp_port=args.mgcp_port,
        skinny_port=args.skinny_port,
        smtp_port=args.smtp_port,
        pop3_port=args.pop3_port,
        imap_port=args.imap_port,
        http_port=args.http_port,
        https_port=args.https_port,
        ftp_port=args.ftp_port,
        irc_port=args.irc_port,
        xmpp_port=args.xmpp_port,
        radius_port=args.radius_port,
        telnet_port=args.telnet_port,
        smtp_starttls=args.smtp_starttls,
        smtp_auth=smtp_auth,
        pop3_ssl=args.pop3_ssl,
        imap_ssl=args.imap_ssl,
        ftp_passive=ftp_passive,
        radius_raw=args.radius_raw,
    )
    blaster.blast_all()


if __name__ == "__main__":
    main()
