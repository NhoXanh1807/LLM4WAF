import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, List, Optional


from wafw00f.main import WAFW00F

def print_banner():
    RESET = "\033[0m"
    BOLD = "\033[1m"
    colors = [
        "\033[32m",
        "\033[36m",
        "\033[34m",
        "\033[35m",
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


CLI_DESCRIPTION = """
LLM4WAF command line interface.

The commands mirror the Flask backend so you can run the same workflow without
starting the web server. JSON inputs and outputs are shaped to match app.py.
""".strip()

