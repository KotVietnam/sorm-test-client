# SORM Client Test

Клиентский генератор трафика для стенда DLP/DPI. Скрипт создает валидный трафик по разным протоколам, чтобы DPI мог его распознать.

## Требования

- Python 3
- Библиотеки:
  - `requests`
  - `scapy`
  - `pyrad`

Установка:

```bash
python3 -m pip install requests scapy pyrad
```

## Запуск

```bash
python3 traffic_generator.py <server_ip>
```

Пример для локального стенда:

```bash
python3 traffic_generator.py 127.0.0.1
```

## Что генерирует

- **VoIP**: SIP OPTIONS, H.323 (через утилиту), IAX2 ping, MGCP AUEP, Skinny keepalive.
- **Почта**: SMTP отправка письма, POP3/IMAP проверка ящика.
- **Web**: HTTP/HTTPS GET и скачивание `rss.xml`.
- **File Transfer**: FTP upload/download тестового файла.
- **Chat**: IRC NICK/USER, XMPP старт XML‑стрима.
- **Misc**: RADIUS Access‑Request, Telnet вход/выход.

## Параметры

```bash
python3 traffic_generator.py <server_ip> \
  --timeout 5 \
  --domain dlp.local \
  --mail-user dlp \
  --mail-pass dlp \
  --ftp-user dlp \
  --ftp-pass dlp \
  --radius-secret testing123 \
  --radius-user dlpuser \
  --radius-pass dlppass \
  --mgcp-endpoint gw1 \
  --rss-path ./data/client/rss.xml
```

Эквивалентные переменные окружения:

- `DLP_DOMAIN`
- `DLP_MAIL_USER`, `DLP_MAIL_PASS`, `DLP_MAIL_FROM`, `DLP_MAIL_TO`
- `DLP_FTP_USER`, `DLP_FTP_PASS`
- `DLP_RADIUS_SECRET`, `DLP_RADIUS_USER`, `DLP_RADIUS_PASS`
- `DLP_MGCP_ENDPOINT`
- `DLP_RSS_PATH`

## Примечания

- Для отправки сырого трафика scapy может потребоваться запуск с повышенными правами.
- H.323 использует внешнюю утилиту `yate-console` или `simph323`; если не найдена — будет предупреждение.
- RSS сохраняется в `./data/client/rss.xml` (папка создается автоматически).
- Значения по умолчанию совпадают с конфигами проекта `sorm-server-test`.
