import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

# Додаємо шлях до батьківської директорії для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпортуємо персональні дані студента
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 9
# Створюємо "сіль" (додатковий рядок для ускладнення хешу),
# доповнюючи номер варіанту нулями зліва до 5 символів ( "00006")
SALT = str(VARIANT_NUMBER).zfill(5)

# Шляхи до файлів бази даних та логів
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


# Власний клас помилки для валідації паролів
class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш пароля з використанням солі та алгоритму BLAKE2s."""
    # Перевірка на порожні значення
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    # Перевірка на мінімальну довжину пароля
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)"
        )

    # Об'єднуємо пароль та сіль, після чого конвертуємо у байти
    data_to_hash = (password + salt).encode("utf-8")

    # Використання алгоритму blake2s (безпечний та швидкий криптографічний хеш)
    return hashlib.blake2s(data_to_hash).hexdigest()


def log_event(func):
    """Декоратор для логування подій (успішних та неуспішних спроб входу) у JSON-файл."""

    @wraps(func)  # Зберігає оригінальне ім'я та документацію функції
    def wrapper(username, password, *args, **kwargs):
        try:
            # Викликаємо оригінальну функцію (в нашому випадку - login)
            res = func(username, password, *args, **kwargs)
            # Визначаємо статус залежно від результату функції
            result_str = "success" if res else "failure"
        except Exception:
            # Якщо сталася помилка під час виконання, записуємо це як невдачу
            result_str = "failure"
            raise  # Виправлено помилку TRY201
        finally:
            # Формуємо запис для логу, який виконається у будь-якому випадку (успіх/помилка)
            log_entry = {
                "event": "login",
                "user": username,
                "result": locals().get("result_str", "failure"),
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),  # Виправлено помилку DTZ005
                "args": list(args),
                "kwargs": kwargs,
            }

            # Створюємо директорію, якщо її не існує
            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []

            # Зчитуємо попередні логи, якщо файл вже існує
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            # Додаємо новий запис та перезаписуємо JSON-файл
            logs.append(log_entry)
            with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=4)

        return res

    return wrapper


def create_user(username: str, password: str) -> tuple:
    """Повертає кортеж (логін, хеш_пароля)."""
    hash_val = generate_hash(password, SALT)
    return (username, hash_val)


def create_users(users_list: list):
    """Створює базу користувачів, валідує їх та зберігає у CSV-файл."""
    os.makedirs(DATA_DIR, exist_ok=True)
    valid_users = []

    # Проходимося по списку користувачів
    for un, pw in users_list:
        try:
            # Спробуємо згенерувати хеш
            user_tuple = create_user(un, pw)
            valid_users.append(user_tuple)
        except (ValueError, ValidationError) as e:
            # Якщо пароль заслабкий або порожній — виводимо помилку і пропускаємо юзера
            print(f"Помилка реєстрації користувача {un}: {e}")

    # Записуємо всіх успішно згенерованих користувачів у CSV
    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "hash_value"])  # Заголовки колонок
        writer.writerows(valid_users)  # Дані


def read_users_db() -> list:
    """Зчитує базу користувачів із CSV-файлу."""
    if not os.path.exists(USERS_CSV_PATH):
        raise FileNotFoundError(f"Файл {USERS_CSV_PATH} не знайдено.")

    users_db = []
    with open(USERS_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # Пропускаємо рядок із заголовками
        for row in reader:
            if row:  # Додаємо рядок, якщо він не порожній
                users_db.append(row)
    return users_db


@log_event  # Застосовуємо декоратор для логування всіх викликів цієї функції
def login(username: str, password: str) -> bool:
    """Функція автентифікації користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    # Завантажуємо базу
    users_db = read_users_db()

    try:
        # Хешуємо введений пароль для порівняння
        input_hash = generate_hash(password, SALT)
    except ValidationError:
        # Якщо введений пароль закороткий, він точно не співпаде з базою
        return False

    # Шукаємо збіг логіна та хеша у базі даних
    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True  # Вхід успішний

    return False  # Користувача не знайдено або пароль невірний


def run_task3():
    """Головна функція для демонстрації роботи коду."""
    print(
        f"=== Завдання 3 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    # Список користувачів для перевірки (включає помилкові дані для тесту валідації)
    users_to_register = (
        ("admin_user", "Admin#2026Secure"),
        ("sec_officer", "Phish1ng@D3tect"),
        ("dev_lead", "Ransomwar3@Protect"),
        ("analyst_01", "S0cial@Engineer"),
        ("guest_account", "12345"),  # Помилка: закороткий пароль
        ("auditor", "Audit@2026Pass"),
        ("net_admin", "Cisco@Packet2026"),
        ("db_admin", "DataBase#Pass1"),
        ("crypto_user", "Crypto@D3tect"),
        ("test_user", "TestingPass123"),
        ("user_lol", ""),  # Помилка: порожній пароль
        ("", "jfjf90e"),  # Помилка: закороткий пароль
    )

    try:
        # 1. Реєстрація (відсіювання невалідних паролів та збереження)
        print("\n1. Реєстрація користувачів та збереження в CSV...")
        create_users(users_to_register)

        # 2. Вивід збереженої бази даних на екран
        print("\n2. Зчитування бази даних з CSV:")
        db = read_users_db()
        print(f"{'Username':<15} | {'BLAKE2S Hash (перші 30 симв.)':<35}")
        print("-" * 55)
        for u, h in db:
            print(f"{u:<15} | {h[:30]}...")

        # 3. Симуляція спроб входу (усі ці спроби будуть записані в log.json)
        print("\n3. Тестування входу (автентифікація):")
        test_logins = [
            ("admin_user", "Admin#2026Secure"),  # Успішно
            ("sec_officer", "WrongPassword"),  # Відмова (невірний пароль)
            ("unknown_user", "SomePass12345"),  # Відмова (немає користувача)
        ]

        for u, p in test_logins:
            status = login(u, p)
            res_str = "УСПІШНО" if status else "ВІДМОВА"
            print(f"Спроба входу user=[{u}] -> {res_str}")

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as err:
        # Глобальне перехоплення критичних помилок
        print(f"\n[ПОМИЛКА ОБРОБКИ]: {err}")


if __name__ == "__main__":
    run_task3()
