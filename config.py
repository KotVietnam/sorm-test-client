# --- НАСТРОЙКИ СЕРВЕРА (Для full_audit.py) ---
# IP адрес машины, где развернут Репозиторий №1
LAB_SERVER_IP = "192.168.1.X"  # <--- ПОМЕНЯТЬ ПРИ ЗАПУСКЕ

# --- КЛЮЧЕВЫЕ СЛОВА (Для DLP триггеров) ---
SECRET_DATA = "CONFIDENTIAL | TOP SECRET | PASSPORT DATA"

# --- НАСТРОЙКИ ПОЧТЫ (Для quick_test.py) ---
# Если хотите тестить реальную отправку через Gmail/Yandex
USE_REAL_SMTP = False
REAL_SMTP_CONF = {
    "server": "smtp.gmail.com",
    "port": 587,
    "user": "mymail@gmail.com",
    "pass": "app_password_here",
    "to": "target@example.com"
}
