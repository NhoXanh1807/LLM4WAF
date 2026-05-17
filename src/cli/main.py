import sys
import os
CORE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../core"))
if CORE_DIR not in sys.path:
    sys.path.append(CORE_DIR)
from modules.command_builder import parse_args_to_command_handler_and_params, verify_and_get_args


def print_banner():
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    colors = [
        "\033[32m",  # xanh lá
        "\033[36m",  # cyan
        "\033[34m",  # xanh dương
        "\033[35m",  # tím
    ]

    banner = r"""
 ___       ___       _____ ______   ________  ___  ___  ___  _______   ___       ________
|\  \     |\  \     |\   _ \  _   \|\   ____\|\  \|\  \|\  \|\  ___ \ |\  \     |\   ___ \
\ \  \    \ \  \    \ \  \\\__\ \  \ \  \___|\ \  \\\  \ \  \ \   __/|\ \  \    \ \  \_|\ \
 \ \  \    \ \  \    \ \  \\|__| \  \ \_____  \ \   __  \ \  \ \  \_|/_\ \  \    \ \  \ \\ \
  \ \  \____\ \  \____\ \  \    \ \  \|____|\  \ \  \ \  \ \  \ \  \_|\ \ \  \____\ \  \_\\ \
   \ \_______\ \_______\ \__\    \ \__\____\_\  \ \__\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|_______|\|__|     \|__|\_________\|__|\|__|\|__|\|_______|\|_______|\|_______|
                                      \|_________|
"""
    for i, line in enumerate(banner.splitlines()):
        c = colors[i % len(colors)]
        print(BOLD + c + line + RESET)

if __name__ == "__main__":
    print_banner()
    args = sys.argv[1:]
    verified_args = verify_and_get_args(args)
    while True:
        handler, params = parse_args_to_command_handler_and_params(verified_args)
        try:
            handler(**params)
        except Exception as e:
            import traceback
            # traceback.print_exc()
            print(f"Error: {e}")
        input("Press Enter to continue...")
        verified_args = verify_and_get_args([])

