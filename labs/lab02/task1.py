import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

# Константи для налаштувань безпеки
SESSION_TIMEOUT_SEC = 900  # Час життя сесії (15 хвилин)
PBKDF2_ITERATIONS = 100_000  # Кількість ітерацій для хешування пароля


# 1. Перелічення Enum для стандартизації дій у журналі аудиту
class Action(Enum):
  LOGIN_SUCCESS = "login_success"
  LOGIN_FAILURE = "login_failure"
  LOGOUT = "logout"


# 2. Базовий клас користувача
class User:

  def __init__(self, username: str, email: str, role: str, active: bool = True):
    self.username = username
    self.email = email  # Звертається до сеттера @email.setter для валідації
    self.role = role
    self.active = active
    # Приховані (private) атрибути для зберігання пароля (починаються з __)
    self.__password_hash: bytes = b""
    self.__password_salt: bytes = b""

  # Декоратор @property перетворює метод на атрибут (геттер)
  @property
  def email(self) -> str:
    return self.__email

  # Сеттер для email із вбудованою валідацією
  @email.setter
  def email(self, value: str):
    # Регулярний вираз для перевірки правильності формату пошти
    pattern = r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, value):
      raise ValueError(f"Некоректний формат email: {value}")
    self.__email = value  # Зберігаємо значення, якщо валідація успішна

  # Метод для безпечного встановлення пароля
  def set_password(self, password: str):
    self.__password_salt = os.urandom(16)  # Генеруємо 16 байт випадкової солі
    # Хешуємо пароль за алгоритмом PBKDF2 з використанням SHA-256
    self.__password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
    )

  # Метод для перевірки введеного пароля
  def check_password(self, password: str) -> bool:
    if not self.__password_hash or not self.__password_salt:
      return False
    # Рахуємо хеш від введеного пароля з тією ж сіллю
    computed_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
    )
    # Безпечне порівняння хешів, стійке до атак за часом (timing attacks)
    return hmac.compare_digest(computed_hash, self.__password_hash)

  def deactivate(self):
    self.active = False

  # Магічний метод для зручного виведення об'єкта через print()
  def __str__(self) -> str:
    return (
        f"User(username='{self.username}', email='{self.email}',"
        f" role='{self.role}', active={self.active})"
    )


# 3. Клас Адміністратора (наслідування від User)
class Admin(User):

  def __init__(
      self, username: str, email: str, permissions: list[str] | None = None
  ):
    # Викликаємо конструктор батьківського класу User (super)
    super().__init__(username, email, role="admin", active=True)
    # Зберігаємо права доступу у вигляді множини (set) для уникнення дублікатів
    self.permissions = set(permissions) if permissions is not None else set()

  def grant_permission(self, permission: str):
    self.permissions.add(permission)

  def revoke_permission(self, permission: str):
    self.permissions.discard(permission)

  def has_permission(self, permission: str) -> bool:
    return permission in self.permissions

  def __str__(self) -> str:
    perms_str = ", ".join(sorted(self.permissions))
    return (
        f"Admin(username='{self.username}', email='{self.email}',"
        f" permissions=[{perms_str}])"
    )


# 4. Клас для управління сесіями
class Session:

  def __init__(self, ip: str, timeout_sec: int = SESSION_TIMEOUT_SEC):
    if timeout_sec <= 0:
      raise ValueError("Timeout має бути додатним числом.")
    self.ip = ip
    # Використовуємо час UTC, щоб уникнути проблем із часовими поясами
    self.login_time = datetime.now(timezone.utc)
    self.last_activity = self.login_time
    self.timeout_sec = timeout_sec

  # Оновлюємо час останньої активності
  def touch(self):
    self.last_activity = datetime.now(timezone.utc)

  # Перевіряємо, чи не закінчився час сесії
  def is_active(self) -> bool:
    now = datetime.now(timezone.utc)
    elapsed = (now - self.last_activity).total_seconds()
    return elapsed <= self.timeout_sec


# 5. Датаклас для окремого запису в журналі (автоматично створює __init__)
@dataclass
class AuditRecord:
  timestamp: datetime
  username: str
  action: Action  # Використовуємо наш клас Enum


# 6. Журнал аудиту
class AuditLog:

  def __init__(self):
    self._records: list[AuditRecord] = []

  def add_log(self, username: str, action: Action):
    record = AuditRecord(
        timestamp=datetime.now(timezone.utc), username=username, action=action
    )
    self._records.append(record)

  def show_all(self):
    for rec in self._records:
      # Форматований вивід часу та події
      print(
          f"[{rec.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}]"
          f" User: {rec.username} | Action: {rec.action.value}"
      )


# 7. Клас Облікового запису (Композиція: містить об'єкти User, Session та AuditLog)
class UserAccount:

  def __init__(self, user: User, session: Session | None = None):
    self.user = user
    self.session = session
    self.audit_log = AuditLog()  # Створюємо власний журнал аудиту

  # Метод входу в систему
  def login(self, password: str, ip: str) -> bool:
    # Якщо користувач деактивований
    if not self.user.active:
      self.audit_log.add_log(self.user.username, Action.LOGIN_FAILURE)
      return False

    # Якщо пароль правильний
    if self.user.check_password(password):
      self.session = Session(ip)  # Створюємо нову сесію
      self.audit_log.add_log(self.user.username, Action.LOGIN_SUCCESS)
      return True
    else:
      # Якщо пароль неправильний
      self.audit_log.add_log(self.user.username, Action.LOGIN_FAILURE)
      return False

  # Метод перевірки авторизації
  def is_authenticated(self) -> bool:
    if self.session is None:
      return False
    if self.session.is_active():
      self.session.touch()  # Подовжуємо сесію при активності
      return True
    else:
      return False

  # Метод виходу
  def logout(self):
    if self.session is not None:
      self.session = None  # Видаляємо сесію
      self.audit_log.add_log(self.user.username, Action.LOGOUT)

  # Спеціальні магічні методи для доступу через квадратні дужки (напр., account["user"])
  def __getitem__(self, key: str):
    if key == "user":
      return self.user
    elif key == "session":
      return self.session
    elif key == "audit_log":
      return self.audit_log
    else:
      raise KeyError(f"Невідомий ключ: {key}")


# Функція для демонстрації роботи Завдання 1
def demo():
  print("=== Демонстрація Завдання 1 ===")
  usr = User("cyber_user", "test.user@gmail.com", "analyst")
  usr.set_password("SecureP@ss123")

  account = UserAccount(usr)
  print(
      "Спроба входу з правильним паролем:",
      account.login("SecureP@ss123", "192.168.1.50"),
  )
  print("Автентифіковано:", account.is_authenticated())

  # Перевірка валідації пошти
  try:
    account["user"].email = "new_email-2026@gmail.com"
    print("Новий email успішно встановлено:", account["user"].email)
  except ValueError as e:
    print("Помилка валідації email:", e)

  # Робота з класом Admin
  admin_usr = Admin(
      "root_admin", "admin.sec@nulp.ua", ["read", "write", "execute"]
  )
  print(admin_usr)
  admin_usr.grant_permission("delete")
  print("Після додавання права delete:", admin_usr.has_permission("delete"))

  # Завершення сесії
  account.logout()
  print("Після виходу автентифіковано:", account.is_authenticated())

  # Виведення всіх подій з журналу
  print("\n--- Записи журналу аутентифікації (AuditLog) ---")
  account.audit_log.show_all()


# Цей блок гарантує, що демо запуститься лише при прямому виконанні файлу
if __name__ == "__main__":
  demo()