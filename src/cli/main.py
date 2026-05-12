import sys
from flask import json

from command_builder import parse_args_to_command_handler_and_params, verify_and_get_args

if __name__ == "__main__":
    args = sys.argv[1:]
    verified_args = verify_and_get_args(args)
    while True:
        handler, params = parse_args_to_command_handler_and_params(verified_args)
        try:
            handler(**params)
        except Exception as e:
            print(f"Error: {e}")
        input("Press Enter to continue...")
        verified_args = verify_and_get_args([])

