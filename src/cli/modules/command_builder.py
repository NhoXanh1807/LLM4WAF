import sys
from modules.handlers import (
    handle_attack_detect,
    handle_attack_generate,
    handle_attack_test,
    handle_defend_cluster,
    handle_defend_genrule,
    handle_defend_rag,
    handle_defend_refine,
    handle_defend_retry,
    handle_defend_validate,
    handle_exit,
    handle_files_all,
    handle_files_remove,
    handle_files_view,
    handle_attack_auto,
    handle_defend_auto,
)

COMMAND_ARGS_BUILDER = {
    "exit": [],
    "files":{
        "all":[],
        "remove": ['file_id'],
        "view": ['file_id'],
    },
    "attack":{
        "detect": ['domain'],
        "generate": ['waf_name', 'attack_type', 'num', 'optional:tested_file'],
        "test": ['domain', 'generate_file'],
        "auto": ['domain', 'attack_type', 'num', 'num_adaptive']
    },
    "defend":{
        "cluster": ['bypassed_file'],
        "rag": ['waf_name', 'attack_type', 'bypassed_file'],
        "genrule": ['waf_name', 'cluster_file', 'optional:rag_file'],
        "validate": ['genrule_file'],
        "retry": ['waf_name', 'invalidrule_file'],
        "refine": ['waf_name', 'validrule_file', 'optional:fixedrule_file', 'optional:existing_rule_file_path'],
        "auto": ['waf_name', 'attack_type', 'bypassed_file', 'optional:existing_rule_file_path']
    }
}


COMMAND_HANDLERS = {
    "exit": handle_exit,
    "files":{
        "all": handle_files_all,
        "remove": handle_files_remove,
        "view": handle_files_view,
    },
    "attack": {
        "detect": handle_attack_detect,
        "generate": handle_attack_generate,
        "test": handle_attack_test,
        "auto": handle_attack_auto,
    },
    "defend": {
        "cluster": handle_defend_cluster,
        "rag": handle_defend_rag,
        "genrule": handle_defend_genrule,
        "validate": handle_defend_validate,
        "retry": handle_defend_retry,
        "refine": handle_defend_refine,
        "auto": handle_defend_auto,
    }
}

def _is_optional_arg(arg_name: str) -> bool:
    return arg_name.startswith("optional:")


def _normalize_arg_name(arg_name: str) -> str:
    return arg_name.split(":", 1)[1] if _is_optional_arg(arg_name) else arg_name


def search_branch(branch, path=None):
    path = path or []
    result = []
    if isinstance(branch, dict):
        for key, sub_branch in branch.items():
            sub_branch_result = search_branch(sub_branch, path + [key])
            result.extend(sub_branch_result)
    elif isinstance(branch, list):
        rendered_args = []
        for arg in branch:
            arg_name = _normalize_arg_name(arg)
            rendered_args.append(f"[{arg_name}]" if _is_optional_arg(arg) else f"<{arg_name}>")
        result.append(path + rendered_args)
    return result

def verify_and_get_args(args) -> list[str|tuple[str, str]]:
    pending_args = list(args)
    args_verified = []
    branch = COMMAND_ARGS_BUILDER
    branch_index = 0

    while True:
        if isinstance(branch, dict):
            if pending_args:
                arg = pending_args.pop(0)
                if arg not in branch:
                    print(f"Unknown command: {arg}")
                    continue
                args_verified.append(arg)
                branch = branch[arg]
                branch_index = 0
                continue

            options = search_branch(branch)
            print("="*10 + " Current command " + "="*10)
            print(" ".join(str(item) for item in args_verified) + " ...")
            print("="*10 + " Available Options " + "="*10)
            for option in options:
                print(">" + (" ".join(option)))
            print("="*10 + " next command " + "="*10)
            user_input = input(">").strip()
            if not user_input:
                continue
            pending_args.extend(user_input.split())
            continue

        if isinstance(branch, list):
            if branch_index >= len(branch):
                if pending_args:
                    print(f"Too many arguments: {' '.join(pending_args)}")
                    sys.exit(1)
                break

            arg_spec = branch[branch_index]
            if pending_args:
                arg_value = pending_args.pop(0)
                args_verified.append((_normalize_arg_name(arg_spec), arg_value))
                branch_index += 1
                continue

            remaining_specs = branch[branch_index:]
            required_remaining = [
                _normalize_arg_name(spec)
                for spec in remaining_specs
                if not _is_optional_arg(spec)
            ]
            if not required_remaining:
                break

            print("="*10 + " Current command " + "="*10)
            print(" ".join(str(item[1]) if isinstance(item, tuple) else item for item in args_verified) + " ...")
            print("="*10 + " Missing Arguments " + "="*10)
            for arg_name in required_remaining:
                print(f"> <{arg_name}>")
            print("="*10 + " next command " + "="*10)
            user_input = input(">").strip()
            if not user_input:
                continue
            pending_args.extend(user_input.split())
            continue

        break

    return args_verified


def parse_args_to_command_handler_and_params(verified_args: list[str|tuple[str, str]]):
    handler = COMMAND_HANDLERS
    params = {}
    for arg in verified_args:
        if isinstance(arg, str) and arg in handler:
            handler = handler[arg]
        elif isinstance(arg, tuple):
            param_name, param_value = arg
            params[param_name] = param_value
    return handler, params

