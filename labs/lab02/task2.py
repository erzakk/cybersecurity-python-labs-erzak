import argparse
import json
import logging
import re
from collections import Counter
from pathlib import Path

# Налаштування логування для виведення інформації про хід роботи у консоль
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def read_passwords_generator(wordlist_path: Path):
  """
  Генератор для порядкового читання великих файлів словників.
  Використання генератора (yield) дозволяє не завантажувати весь файл у пам'ять цілком.
  Це критично важливо при обробці величезних словників паролів на гігабайти.
  """
  try:
    # Відкриваємо файл на читання з ігноруванням помилок кодування
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
      for line in f:
        pwd = line.strip()  # Видаляємо пробіли та символи нового рядка з кінців
        if pwd:
          yield pwd  # Повертаємо пароль по одному за запитом
  except OSError as e:  # Ловимо специфічну помилку роботи з файлами (виправлення BLE001)
    logger.error(f"Помилка читання файлу словника {wordlist_path}: {e}")


def get_password_mask_name(password: str) -> str:
  """
  Аналізує маску пароля за допомогою регулярних виразів (модуль re).
  Визначає, які типи символів (літери, цифри, спецсимволи) містяться в паролі.
  """
  # re.search шукає хоча б один збіг із регулярним виразом
  has_upper = bool(re.search(r"[A-Z]", password))  # Велика літера
  has_lower = bool(re.search(r"[a-z]", password))  # Мала літера
  has_digit = bool(re.search(r"\d", password))     # Цифра
  has_special = bool(re.search(r"[^a-zA-Z0-9]", password)) # Спецсимвол (все, що не літера і не цифра)

  # Класифікуємо пароль за виявленими символами
  if has_upper and has_lower and has_digit and has_special:
    return "Complex (Upper-Lower-Digit-Special)"
  elif has_upper and has_lower and has_digit:
    return "Upper-Lower-Digit (UlLd)"
  elif has_lower and has_digit and not has_upper and not has_special:
    return "Lowercase-Digit (LdLd)"
  elif has_lower and not has_upper and not has_digit and not has_special:
    return "All-Lowercase (LLLL)"
  elif has_digit and not has_lower and not has_upper and not has_special:
    return "All-Digits (dddd)"
  else:
    return "Other / Mixed"


def main():
  # Ініціалізуємо парсер аргументів командного рядка
  parser = argparse.ArgumentParser(
      description="Password Dictionary Audit & Mask Analyzer (Variant 6)"
  )
  
  # Додаємо очікувані аргументи (--wordlist, --min-length тощо)
  parser.add_argument(
      "--wordlist",
      type=str,
      required=True, # Обов'язковий аргумент
      help="Шлях до файлу зі словником паролів",
  )
  parser.add_argument(
      "--min-length",
      type=int,
      default=8,     # Значення за замовчуванням
      help="Мінімальна довжина для слабкого пароля (дефолт: 8)",
  )
  parser.add_argument(
      "--top-masks",
      type=int,
      default=5,
      help="Кількість топових масок для виведення (дефолт: 5)",
  )
  parser.add_argument(
      "--output-stats", type=str, required=True, help="Шлях для збереження JSON-звіту"
  )

  # Парсимо (зчитуємо) передані з термінала аргументи
  args = parser.parse_args()

  # Перетворюємо рядок шляху на об'єкт Path для зручнішої роботи
  wordlist_path = Path(args.wordlist)
  logger.info(f"Processing dictionary file {wordlist_path} using generators...")

  # Змінні для ведення статистики
  total_passwords = 0
  weak_passwords_count = 0
  total_length = 0
  
  # Counter з collections автоматично підраховує кількість повторень кожного елемента
  mask_counter = Counter()

  # Проходимося по кожному паролю, використовуючи наш генератор
  for pwd in read_passwords_generator(wordlist_path):
    total_passwords += 1
    total_length += len(pwd)

    # Перевіряємо, чи є пароль "слабким" за довжиною
    if len(pwd) < args.min_length:
      weak_passwords_count += 1

    # Отримуємо маску пароля та збільшуємо лічильник для неї у Counter
    mask_name = get_password_mask_name(pwd)
    mask_counter[mask_name] += 1

  # Якщо файл порожній або не прочитався, завершуємо роботу
  if total_passwords == 0:
    logger.warning("Словник порожній або файл не вдалося прочитати.")
    return

  logger.info(f"Analyzed {total_passwords:,} passwords.")

  # Розраховуємо середні значення (відсотки та довжину)
  avg_length = total_length / total_passwords
  weak_percentage = (weak_passwords_count / total_passwords) * 100

  # Виведення результатів аудиту в консоль
  print("\n=== Password Dictionary Audit Summary ===")
  print(f"Total Passwords     : {total_passwords:,}")
  print(
      f"Weak Passwords (<{args.min_length}): {weak_passwords_count:,}"
      f" ({weak_percentage:.1f}%)"
  )
  print(f"Average Length      : {avg_length:.1f} characters")

  print(f"\n=== Top-{args.top_masks} Password Masks ===")
  # Отримуємо ТОП найпопулярніших масок через зручний метод most_common()
  top_masks = mask_counter.most_common(args.top_masks)
  
  # enumerate(..., start=1) автоматично додає нумерацію з одиниці (1, 2, 3...)
  for idx, (mask, count) in enumerate(top_masks, start=1):
    percentage = (count / total_passwords) * 100
    print(f"{idx}. {mask:35} : {count:,} ({percentage:.1f}%)")

  # Формуємо словник (dict) із результатами для подальшого експорту в JSON
  report_data = {
      "total_passwords": total_passwords,
      "min_length_threshold": args.min_length,
      "weak_passwords_count": weak_passwords_count,
      "weak_passwords_percentage": round(weak_percentage, 2),
      "average_length": round(avg_length, 2),
      "top_masks": [
          {
              "mask": m,
              "count": c,
              "percentage": round((c / total_passwords) * 100, 2),
          }
          for m, c in top_masks
      ],
  }

  # Створюємо необхідні папки, якщо їх ще не існує (exist_ok=True не видає помилку, якщо папка вже є)
  out_file = Path(args.output_stats)
  out_file.parent.mkdir(parents=True, exist_ok=True)
  
  # Записуємо словник report_data у JSON файл
  with open(out_file, "w", encoding="utf-8") as f:
    json.dump(report_data, f, ensure_ascii=False, indent=2)

  logger.info(f"Dictionary statistics saved to {out_file}")


# Точка входу в скрипт
if __name__ == "__main__":
  main()