import os
import sys

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані згідно з варіантом
users = {
    "red_team_lead": {"role": "red_team", "clearance": 4, "department": "Red Team", "active": True},
    "blue_team_analyst": {"role": "blue_team", "clearance": 3, "department": "Blue Team", "active": True},
    "purple_team_coord": {"role": "purple_team", "clearance": 3, "department": "Purple Team", "active": True},
    "student_intern": {"role": "student", "clearance": 1, "department": "Academia", "active": True},
    "retired_expert": {"role": "retired", "clearance": 2, "department": "Emeritus", "active": False}
}

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
    ("public_research", 1)
]

security_levels = ("Academic", "Operational", "Tactical", "Strategic")
blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def check_access(user_id: str, resource_name: str, resource_level: int) -> str:
    # Перевірка, чи існує користувач у системі
    if user_id not in users:
        return "DENY (User not found)"

    # Перевірка, чи знаходиться користувач у списку заблокованих
    if user_id in blocked_users:
        return "DENY (User is blocked)"

    user_info = users[user_id]

    # Перевірка, чи активний обліковий запис
    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    user_clearance = user_info.get("clearance", 0)

    # Основна перевірка допуску до ресурсу
    if user_clearance >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def run_task2():
    print(
        f"=== Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    print("\n--- Список ресурсів системи ---")
    for res_name, res_level in resources:
        # Перетворення номера рівня на назву (індекс на 1 менший за рівень)
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень: {level_name}")

    print("\n--- Результати перевірки доступу ---")

    # Створення списку користувачів для тестування (включаючи неіснуючого)
    test_user_ids = list(users.keys()) + ["guest_user", "leaked_account"]

    for u_id in test_user_ids:
        for res_name, res_level in resources:
            result = check_access(u_id, res_name, res_level)
            print(f"user=[{u_id}] resource=[{res_name}] -> {result}")


if __name__ == "__main__":
    run_task2()
