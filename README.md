# SORM Test Client

Клиентский генератор трафика для стенда DLP/DPI. Скрипт создает валидный трафик по разным протоколам, чтобы DPI мог его распознать.

## Требования

- Python 3
- Библиотеки:
  - `requests`
  - `scapy`
  - `pyrad`
  - `slixmpp` (для XMPP)
  - `colorama` (для красивого цветного вывода на Windows)

Установка:

```bash
python3 -m pip install -r requirements.txt
```

## Запуск

Скрипт максимально упрощен для "one-click" запуска.

```bash
# Запустит все тесты для сервера 127.0.0.1 и откроет сайты в браузере
python3 traffic_generator.py
```

При необходимости IP адрес сервера можно указать как аргумент:

```bash
python3 traffic_generator.py 192.168.1.100
```

Также можно задать IP через `.env` (ключ `DLP_SERVER_IP`).

## Что генерирует

- **VoIP**: `SIP OPTIONS` и `REGISTER`, совершает полноценный звонок с RTP-аудиопотоком, H.323 (через утилиту), IAX2 ping, MGCP AUEP, Skinny keepalive.
- **Почта**: SMTP отправка письма, POP3/IMAP проверка ящика.
- **Web**: HTTP/HTTPS GET и скачивание `rss.xml`.
- **Browser (по умолчанию)**: открытие публичных сайтов в браузере (`http://kremlin.ru`, `WhatsApp`, `Telegram`, `Instagram`, `Skype`).
- **File Transfer**: FTP upload/download тестового файла.
- **Chat**: 
  - **IRC**: Подключается к серверу, заходит на канал `#test` и отправляет сообщение.
  - **XMPP**: Регистрирует нового случайного пользователя, логинится и отправляет сообщение.
- **Misc**: RADIUS Access‑Request, Telnet вход/выход.

## Параметры

Чтобы запустить скрипт без открытия браузера:
```bash
python3 traffic_generator.py 127.0.0.1 --open-sites=false
```

Другие параметры (порты, пользователи, пароли) можно переопределить через аргументы командной строки или переменные в `.env` файле.

Пример:
```bash
python3 traffic_generator.py 127.0.0.1 \
  --timeout 5 \
  --domain dlp.local \
  --mail-user dlp \
  --mail-pass dlp \
  --open-sites
```

Открыть конкретные сайты:

```bash
python3 traffic_generator.py <server_ip> --sites "http://example.com,https://google.com"
```

Пример с портами и TLS/SSL:

```bash
python3 traffic_generator.py <server_ip> \
  --smtp-port 3025 --pop3-port 3110 --imap-port 3143 \
  --smtp-starttls --pop3-ssl --imap-ssl \
  --ftp-port 21 --ftp-active \
  --radius-port 1812 --radius-raw
```

## .env

Скрипт автоматически читает `.env` из текущей папки. Если файл лежит в другом месте, укажите путь:

```bash
python3 traffic_generator.py --env-file C:\\path\\to\\.env
```

Эквивалентные переменные окружения:

- `DLP_SERVER_IP`, `DLP_TIMEOUT`, `DLP_DOMAIN`
- `DLP_MAIL_USER`, `DLP_MAIL_PASS`, `DLP_MAIL_FROM`, `DLP_MAIL_TO`
- `DLP_SMTP_PORT`, `DLP_POP3_PORT`, `DLP_IMAP_PORT`
- `DLP_SMTP_STARTTLS`, `DLP_SMTP_NO_AUTH`, `DLP_POP3_SSL`, `DLP_IMAP_SSL`
- `DLP_FTP_USER`, `DLP_FTP_PASS`
- `DLP_FTP_PORT`, `DLP_FTP_ACTIVE`
- `DLP_RADIUS_SECRET`, `DLP_RADIUS_USER`, `DLP_RADIUS_PASS`
- `DLP_RADIUS_PORT`, `DLP_RADIUS_RAW`
- `DLP_HTTP_PORT`, `DLP_HTTPS_PORT`
- `DLP_MGCP_ENDPOINT`
- `DLP_SIP_PORT`, `DLP_IAX2_PORT`, `DLP_MGCP_PORT`, `DLP_SKINNY_PORT`
- `DLP_IRC_PORT`, `DLP_XMPP_PORT`, `DLP_TELNET_PORT`
- `DLP_RSS_PATH`
- `DLP_SITES`

## Примечания

- Для отправки сырого трафика scapy может потребоваться запуск с повышенными правами.
- H.323 использует внешнюю утилиту `yate-console` или `simph323`; если не найдена — будет предупреждение.
- Цветной вывод можно отключить через `NO_COLOR=1`.
- Значения по умолчанию совпадают с конфигами проекта `sorm-test-server`.
