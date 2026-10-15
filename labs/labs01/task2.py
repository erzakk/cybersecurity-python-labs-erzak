import os
import sys

# Додаємо шлях до батьківської директорії, щоб програма могла знайти і імпортувати модуль shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпортуємо персональні дані студента (ім'я, групу, варіант) з іншого файлу
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Словник (база даних) користувачів.
# Ключ — це логін (user_id), а значення — словник з його атрибутами
# роль, рівень допуску (clearance), відділ та статус (чи активний акаунт).
users = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "Red Team",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}


# Список ресурсів системи.
# Кожен елемент — це кортеж: (назва_ресурсу, мінімальний_рівень_доступу_до_нього)
resources = [
    ("attack_scenarios", 4),
    ("defense_playbooks", 3),
    ("exercise_plans", 3),
    ("research_papers", 1),
    ("exploit_tools", 4),
    ("student_resources", 1),
    ("simulation_results", 3),
    ("red_team_tools", 4),
    ("blue_team_reports", 3),
    ("public_research", 1),
]

# Текстові назви рівнів безпеки.
# Індекс 0 відповідає рівню 1 ("Academic"), індекс 1 — рівню 2 тощо.
security_levels = ("Academic", "Operational", "Tactical", "Strategic")

# Чорний список (множина) користувачів, яким доступ заборонено глобально.
blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def check_access(user_id: str, resource_name: str, resource_level: int) -> str:
    """Функція для перевірки, чи має користувач доступ до конкретного ресурсу."""

    # 1. Перевірка, чи взагалі існує такий користувач у нашій "базі" (словнику users)
    if user_id not in users:
        return "DENY (User not found)"

    # 2. Перевірка, чи не знаходиться цей користувач у чорному списку
    if user_id in blocked_users:
        return "DENY (User is blocked)"

    # Отримуємо дані користувача, якщо він пройшов попередні перевірки
    user_info = users[user_id]

    # 3. Перевірка, чи активний обліковий запис. Якщо ключа "active" немає, за замовчуванням беремо False
    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    # Отримуємо рівень допуску користувача (якщо не вказано, то 0)
    user_clearance = user_info.get("clearance", 0)

    # 4. Основна перевірка доступу
    # Рівень допуску юзера має бути більшим або рівним необхідному рівню ресурсу
    if user_clearance >= resource_level:
        return "ALLOW"

    # Якщо рівень допуску замалий
    return "DENY (Insufficient clearance)"


def run_task2():
    """Головна функція для запуску симуляції та виводу результатів."""

    # Виводимо гарну шапку з данними
    print(
        f"=== Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    # Виводимо список усіх ресурсів та їхні текстові рівні доступу
    print("\n--- Список ресурсів системи ---")
    for res_name, res_level in resources:
        # Перетворення номера рівня на назву (оскільки індекси починаються з 0, віднімаємо 1)
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень: {level_name}")

    print("\n--- Результати перевірки доступу ---")

    # Створюємо список користувачів для тестування.
    # Беремо всіх існуючих користувачів з бази та штучно додаємо двох проблемних для перевірки логіки відмов.
    test_user_ids = list(users.keys()) + ["guest_user", "leaked_account"]

    # Проходимося по кожному користувачеві з тестового списку
    for u_id in test_user_ids:
        # Для кожного користувача перевіряємо доступ до КОЖНОГО ресурсу зі списку
        for res_name, res_level in resources:
            # Викликаємо функцію перевірки доступу
            result = check_access(u_id, res_name, res_level)
            # Виводимо результат у консоль
            print(f"user=[{u_id}] resource=[{res_name}] -> {result}")


# Стандартна точка входу в Python: якщо файл запускається напряму, викликати run_task2()
if __name__ == "__main__":
    run_task2()
