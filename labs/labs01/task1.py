import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Pr0t3ct@Data",
    "default",
    "Fuur1256",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"simple123", "public", "basic123", "temp123", "default", "guest"}


def analyze_password(pwd: str, is_duplicate: bool) -> str:
    min_len = criteria["min_length"]

    if pwd in forbidden_passwords or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_spec = any(not c.isalnum() for c in pwd)

    met_count = sum([has_digit, has_upper, has_lower, has_spec])
    all_criteria_met = met_count == 4

    # Якщо всі умови виконані, довжина достатня і це ПЕРША поява пароля
    if all_criteria_met and len(pwd) >= min_len + 4 and not is_duplicate:
        return "Дуже сильний"

    # Якщо він був "Дуже сильним", але це вже його дублікат (is_duplicate == True),
    # він не пройде умову вище і отримає статус "Сильний"
    if all_criteria_met:
        return "Сильний"

    if 1 < met_count < 4:
        return "Середній"

    return "Слабкий"


def run_task1():
    print(
        f"=== Завдання 1 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    pwd_list = passwords.copy()

    # Знаходимо індекси всіх паролів, які потенційно є "Дуже сильними",
    # щоб гарантовано вибрати хоча б один для демонстрації дублювання
    very_strong_indices = [
        i
        for i, p in enumerate(pwd_list)
        if analyze_password(p, is_duplicate=False) == "Дуже сильний"
    ]

    dup_indices = []

    # 1. Беремо випадковий "Дуже сильний" пароль (якщо такі є)
    if very_strong_indices:
        dup_indices.append(random.choice(very_strong_indices))

    # 2. Добираємо інші випадкові паролі до 3-х штук
    remaining_indices = list(set(range(len(pwd_list))) - set(dup_indices))
    dup_indices.extend(random.sample(remaining_indices, 3 - len(dup_indices)))

    # Додаємо вибрані дублікати в кінець списку
    for idx in dup_indices:
        pwd_list.append(pwd_list[idx])

    print("\nРезультати аналізу паролів:")
    print(f"{'Пароль':<22} | {'Статус':<20}")
    print("-" * 45)

    # Множина для відстеження паролів, які ми вже перевірили
    seen_passwords = set()

    for pwd in pwd_list:
        # Пароль вважається дублікатом, якщо він вже є у множині seen_passwords
        is_duplicate = pwd in seen_passwords

        # Додаємо пароль до множини перевірених
        seen_passwords.add(pwd)

        # Передаємо стан is_duplicate у функцію
        status = analyze_password(pwd, is_duplicate)
        print(f"{pwd:<22} | {status:<20}")


if __name__ == "__main__":
    run_task1()
