import os
import random
import sys

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


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
    "default"
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "simple123", 
    "public", 
    "basic123", 
    "temp123", 
    "default", 
    "guest"
}


def analyze_password(pwd: str, all_pwds: list) -> str:
    min_len = criteria["min_length"]
    

    if pwd in forbidden_passwords or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_spec = any(not c.isalnum() for c in pwd)

    all_criteria_met = (
        has_digit and has_upper and has_spec
    )
    is_unique = all_pwds.count(pwd) == 1

    if all_criteria_met:
        if len(pwd) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"


    met_count = sum([has_digit, has_upper, has_lower, has_spec])
    if len(pwd) >= min_len and met_count >= 2:
        return "Середній"
        
   
    return "Слабкий"


def run_task1():
    print(f"=== Завдання 1 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ===")

    pwd_list = passwords.copy()
    random.seed(42)
    
    
    dup_indices = random.sample(range(len(pwd_list)), 3)
    for idx in dup_indices:
        pwd_list.append(pwd_list[idx])

    print("\nРезультати аналізу паролів:")
    print(f"{'Пароль':<22} | {'Статус':<20}")
    print("-" * 45)

    for pwd in pwd_list:
        status = analyze_password(pwd, pwd_list)
        print(f"{pwd:<22} | {status:<20}")


if __name__ == "__main__":
    run_task1()