import sys

from labs.lab02.task1 import demo as demo_task1
from labs.lab02.task2 import main as run_task2


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo_task1()
    else:
        run_task2()


if __name__ == "__main__":
    main()
