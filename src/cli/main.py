import argparse
import json
import os
import re
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../core")))

from dtos import PayloadResult
from pipelines import attack, defend


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUTS_DIR = REPO_ROOT / "outputs"
OUTPUTS_INDEX_PATH = OUTPUTS_DIR / "index.json"
OUTPUT_TYPE_PREFIXES = {
    "attack.detect-waf": "waf",
    "attack.generate-random": "rdpayload",
    "attack.generate-adaptive": "adpayload",
    "attack.test": "attack",
    "defend.clustering": "cluster",
    "defend.rag-retrieve": "rag",
    "defend.generate-rules": "genrule",
    "defend.validate-valid": "validrule",
    "defend.validate-invalid": "invalidrule",
    "defend.retry-invalid-rules": "fixedrule",
    "defend.refine-rules": "finalrule",
}


def print_banner() -> None:
    reset = "\033[0m"
    bold = "\033[1m"
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
        color = colors[i % len(colors)]
        print(bold + color + line + reset)


print_banner()


def ensure_output_store() -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    if not OUTPUTS_INDEX_PATH.exists():
        OUTPUTS_INDEX_PATH.write_text(
            json.dumps({"counters": {}, "items": []}, indent=2),
            encoding="utf-8",
        )


def normalize_output_index(index_data: Any) -> dict[str, Any]:
    if not isinstance(index_data, dict):
        index_data = {}

    items = index_data.get("items", [])
    if not isinstance(items, list):
        items = []

    counters = index_data.get("counters", {})
    if not isinstance(counters, dict):
        counters = {}

    for item in items:
        file_id = str(item.get("id", ""))
        match = re.fullmatch(r"([a-z]+)(\d+)", file_id)
        if not match:
            continue
        prefix = match.group(1)
        next_value = int(match.group(2)) + 1
        counters[prefix] = max(int(counters.get(prefix, 0)), next_value)

    return {
        "counters": counters,
        "items": items,
    }


def load_output_index() -> dict[str, Any]:
    ensure_output_store()
    index_data = json.loads(OUTPUTS_INDEX_PATH.read_text(encoding="utf-8"))
    normalized = normalize_output_index(index_data)
    if normalized != index_data:
        save_output_index(normalized)
    return normalized


def save_output_index(index_data: dict[str, Any]) -> None:
    ensure_output_store()
    OUTPUTS_INDEX_PATH.write_text(json.dumps(index_data, indent=2), encoding="utf-8")


def serialize_json(data: Any) -> Any:
    if is_dataclass(data):
        return {key: serialize_json(value) for key, value in asdict(data).items()}
    if isinstance(data, Enum):
        return data.value
    if isinstance(data, dict):
        return {str(key): serialize_json(value) for key, value in data.items()}
    if isinstance(data, (list, tuple)):
        return [serialize_json(value) for value in data]
    return data


def save_output_file(output_type: str, payload: Any) -> dict[str, Any]:
    ensure_output_store()
    index_data = load_output_index()

    output_prefix = OUTPUT_TYPE_PREFIXES.get(output_type)
    if not output_prefix:
        raise ValueError(f"Unsupported output type: {output_type}")

    counter = int(index_data["counters"].get(output_prefix, 0))
    file_id = f"{output_prefix}{counter}"
    relative_path = Path("outputs") / f"{file_id}.json"
    absolute_path = REPO_ROOT / relative_path

    absolute_path.write_text(json.dumps(serialize_json(payload), indent=2), encoding="utf-8")

    record = {
        "id": file_id,
        "output_type": output_prefix,
        "source_command": output_type,
        "path": relative_path.as_posix(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    index_data["items"].append(record)
    index_data["counters"][output_prefix] = counter + 1
    save_output_index(index_data)
    return record


def find_output_record(file_id: str) -> dict[str, Any]:
    index_data = load_output_index()
    for item in index_data.get("items", []):
        if item.get("id") == file_id:
            return item
    raise ValueError(f"Unknown file id: {file_id}")


def resolve_input_path(file_path: Optional[str], file_id: Optional[str]) -> Path:
    if file_id:
        record = find_output_record(file_id)
        return REPO_ROOT / Path(record["path"])
    if file_path:
        return Path(file_path).resolve()
    raise ValueError("Either a file path or a file id must be provided")


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json_input(file_path: Optional[str], file_id: Optional[str]) -> Any:
    return read_json_file(resolve_input_path(file_path, file_id))


def payload_result_from_mapping(item: dict[str, Any]) -> PayloadResult:
    return PayloadResult(
        payload=item.get("payload", ""),
        technique=item.get("technique", ""),
        attack_type=item.get("attack_type", ""),
        status_code=item.get("status_code"),
        is_bypassed=item.get("is_bypassed"),
        is_harmful=item.get("is_harmful"),
    )


def extract_payload_results(data: Any) -> list[PayloadResult]:
    if isinstance(data, dict) and isinstance(data.get("payloads"), list):
        raw_payloads = data["payloads"]
    elif isinstance(data, list):
        raw_payloads = data
    else:
        raise ValueError("Payload input must be a JSON list or an object with a 'payloads' field")

    return [payload_result_from_mapping(item) for item in raw_payloads if isinstance(item, dict)]


def extract_bypassed_payloads(data: Any) -> list[str]:
    if isinstance(data, dict) and isinstance(data.get("bypassed_payloads"), list):
        return [str(item).strip() for item in data["bypassed_payloads"] if str(item).strip()]

    if isinstance(data, dict) and isinstance(data.get("payloads"), list):
        payloads = data["payloads"]
    elif isinstance(data, list):
        payloads = data
    else:
        raise ValueError("Bypassed payload input must be a JSON list or an object with payload fields")

    results: list[str] = []
    for item in payloads:
        if isinstance(item, str) and item.strip():
            results.append(item.strip())
        elif isinstance(item, dict):
            payload = str(item.get("payload", "")).strip()
            if payload and item.get("is_bypassed", True):
                results.append(payload)
    return results


def extract_clusters(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("clusters"), list):
        return data["clusters"]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    raise ValueError("Clusters input must be a JSON list or an object with a 'clusters' field")


def extract_rag_context(path: Path) -> str:
    if path.suffix.lower() == ".json":
        data = read_json_file(path)
        if isinstance(data, dict) and isinstance(data.get("rag_context"), str):
            return data["rag_context"]
        raise ValueError("JSON RAG context input must contain a 'rag_context' field")
    return read_text_file(path)


def extract_rules_field(data: Any, field_name: str) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get(field_name), list):
        return [item for item in data[field_name] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    raise ValueError(f"Rules input must be a JSON list or an object with a '{field_name}' field")


def load_existing_rules(file_path: Optional[str], file_id: Optional[str]) -> Optional[list[str]]:
    if not file_path and not file_id:
        return None
    raw_text = read_text_file(resolve_input_path(file_path, file_id))
    parsed_rules = defend._parse_existing_rules([raw_text])
    return parsed_rules or None


def print_saved_output(record: dict[str, Any], payload: Any) -> None:
    print(json.dumps({
        "saved": {
            "id": record["id"],
            "output_type": record["output_type"],
            "source_command": record["source_command"],
            "path": record["path"],
        },
        "output": serialize_json(payload),
    }, indent=2))


def add_json_file_input(
    parser: argparse.ArgumentParser,
    name: str,
    help_text: str,
    file_id_flag: str,
    required: bool = True,
) -> None:
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument(f"--{name}-file", help=help_text)
    group.add_argument(
        f"--f-{file_id_flag}",
        dest=f"{name.replace('-', '_')}_file_id",
        help=f"Stored output id for {name.replace('-', ' ')}",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python main.py",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
    )

    subparsers = parser.add_subparsers(dest="pipeline", metavar="{attack,defend,outputs}")

    attack_parser = subparsers.add_parser(
        "attack",
        help="Run attack pipeline steps",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    attack_subparsers = attack_parser.add_subparsers(dest="attack_command", metavar="{detect-waf,generate-payload,test,run}")

    attack_detect = attack_subparsers.add_parser("detect-waf", help="Step 1 - detect target WAF")
    attack_detect.add_argument("--domain", required=True, help="Target domain or base URL")

    attack_generate = attack_subparsers.add_parser("generate-payload", help="Step 2 - generate attack payloads")
    attack_generate.add_argument("--waf-name", required=True, help="Detected WAF name")
    attack_generate.add_argument("--attack-type", required=True, help="Attack type, e.g. sql_injection or xss_reflected")
    attack_generate.add_argument("--num-payloads", type=int, default=5, help="Number of payloads to generate")
    add_json_file_input(
        attack_generate,
        "payloads-history",
        "Optional JSON file containing previous payload results for adaptive generation",
        "history",
        required=False,
    )

    attack_test = attack_subparsers.add_parser("test", help="Step 3 - test payloads against DVWA")
    attack_test.add_argument("--domain", required=True, help="Target domain or base URL")
    add_json_file_input(attack_test, "payloads", "JSON file containing payload list", "payloads")
    attack_test.add_argument(
        "--skip-harmful-check",
        action="store_true",
        help="Skip XSS/SQL harmfulness analysis before testing",
    )

    attack_run = attack_subparsers.add_parser("run", help="Run the full attack pipeline")
    attack_run.add_argument("--domain", required=True, help="Target domain or base URL")
    attack_run.add_argument("--attack-type", required=True, help="Attack type, e.g. sql_injection or xss_reflected")
    attack_run.add_argument("--num-payloads", type=int, default=5, help="Number of initial payloads")
    attack_run.add_argument("--adaptive", action="store_true", help="Enable adaptive payload generation")
    attack_run.add_argument("--adaptive-count", type=int, default=5, help="Number of adaptive payloads")

    defend_parser = subparsers.add_parser(
        "defend",
        help="Run defend pipeline steps",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    defend_subparsers = defend_parser.add_subparsers(
        dest="defend_command",
        metavar="{clustering,rag-retrieve,generate-rules,validate-rules,retry-invalid-rules,refine-rules,run}",
    )

    defend_clustering = defend_subparsers.add_parser("clustering", help="Step 1 - cluster bypassed payloads")
    add_json_file_input(defend_clustering, "bypassed-payloads", "JSON file containing bypassed payload results", "payloads")
    defend_clustering.add_argument("--attack-type", required=True, help="Attack type attached to the clustered payloads")

    defend_rag = defend_subparsers.add_parser("rag-retrieve", help="Step 2 - retrieve relevant WAF sources")
    defend_rag.add_argument("--waf-name", required=True, help="Detected WAF name")
    defend_rag.add_argument("--attack-type", required=True, help="Attack type for retrieval context")
    add_json_file_input(defend_rag, "bypassed-payloads", "JSON file containing bypassed payload strings or results", "payloads")

    defend_generate = defend_subparsers.add_parser("generate-rules", help="Step 3 - generate WAF rules")
    defend_generate.add_argument("--waf-name", required=True, help="Detected WAF name")
    add_json_file_input(defend_generate, "clusters", "JSON file containing clustering output", "clusters")
    add_json_file_input(defend_generate, "rag-context", "Text or JSON file containing combined RAG context", "rag")

    defend_validate = defend_subparsers.add_parser("validate-rules", help="Step 4 - validate generated rules")
    add_json_file_input(defend_validate, "generated-rules", "JSON file containing generated rules", "genrules")

    defend_retry = defend_subparsers.add_parser("retry-invalid-rules", help="Step 5 - retry invalid rules")
    defend_retry.add_argument("--waf-name", required=True, help="Detected WAF name")
    add_json_file_input(defend_retry, "invalid-rules", "JSON file containing invalid rules", "invalidrules")

    defend_refine = defend_subparsers.add_parser("refine-rules", help="Step 6 - refine final rules")
    defend_refine.add_argument("--waf-name", required=True, help="Detected WAF name")
    add_json_file_input(defend_refine, "valid-rules", "JSON file containing valid or fixed rules", "validrules")
    add_json_file_input(
        defend_refine,
        "existing-rules",
        "Optional text or JSON file containing existing WAF rules to merge with",
        "existingrules",
        required=False,
    )

    defend_run = defend_subparsers.add_parser("run", help="Run the full defend pipeline")
    defend_run.add_argument("--waf-name", required=True, help="Detected WAF name")
    defend_run.add_argument("--attack-type", required=True, help="Attack type for clustering and retrieval")
    add_json_file_input(defend_run, "bypassed-payloads", "JSON file containing bypassed payload results", "payloads")
    add_json_file_input(
        defend_run,
        "existing-rules",
        "Optional text or JSON file containing existing WAF rules to merge with",
        "existingrules",
        required=False,
    )

    outputs_parser = subparsers.add_parser(
        "outputs",
        help="Inspect or remove stored step outputs",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    outputs_subparsers = outputs_parser.add_subparsers(dest="outputs_command", metavar="{list,remove}")

    outputs_list = outputs_subparsers.add_parser("list", help="List saved output files")
    outputs_list.add_argument("--type", help="Optional filter by short output type, e.g. cluster, rag, genrule, attack")

    outputs_remove = outputs_subparsers.add_parser("remove", help="Remove a saved output file by id")
    outputs_remove.add_argument("--id", required=True, help="Saved output id to remove")

    return parser


def print_cli_help(parser: argparse.ArgumentParser) -> None:
    examples = """
Suggested usage

Attack pipeline
  python main.py attack detect-waf --domain http://modsec.llmshield.click
  python main.py attack generate-payload --waf-name ModSecurity --attack-type sql_injection --num-payloads 5
  python main.py attack generate-payload --waf-name ModSecurity --attack-type sql_injection --num-payloads 5 --f-history attack0
  python main.py attack test --domain http://modsec.llmshield.click --f-payloads rdpayload0
  python main.py attack run --domain http://modsec.llmshield.click --attack-type sql_injection --num-payloads 5 --adaptive --adaptive-count 5

Defend pipeline
  python main.py defend clustering --f-payloads attack0 --attack-type sql_injection
  python main.py defend rag-retrieve --waf-name ModSecurity --attack-type sql_injection --f-payloads attack0
  python main.py defend generate-rules --waf-name ModSecurity --f-clusters cluster0 --f-rag rag0
  python main.py defend validate-rules --f-genrules genrule0
  python main.py defend retry-invalid-rules --waf-name ModSecurity --f-invalidrules invalidrule0
  python main.py defend refine-rules --waf-name ModSecurity --f-validrules validrule0 --existing-rules-file ./existing_rules.txt
  python main.py defend run --waf-name ModSecurity --attack-type sql_injection --f-payloads attack0

Stored outputs
  python main.py outputs list
  python main.py outputs list --type genrule
  python main.py outputs remove --id invalidrule0

Conventions
  - Every command auto-saves its JSON output into outputs/.
  - Reuse a previous step by passing --f-* instead of a file path.
  - File ids are counted independently per output type: cluster0, rag0, genrule0, validrule0, invalidrule0, fixedrule0, finalrule0, rdpayload0, adpayload0, attack0.
  - outputs/index.json maps file ids to path, output type, and source command.
""".strip()

    print()
    print(parser.format_help().rstrip())
    print()
    print(examples)


def execute_attack_detect(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    output = attack._1_detect_waf(parsed_args.domain)
    return output, "attack.detect-waf"


def execute_attack_generate(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    payload_history_data = None
    if parsed_args.payloads_history_file or parsed_args.payloads_history_file_id:
        payload_history_data = read_json_input(parsed_args.payloads_history_file, parsed_args.payloads_history_file_id)
    payload_history = extract_payload_results(payload_history_data) if payload_history_data is not None else []

    payloads = attack._2_generate_payload(
        waf_name=parsed_args.waf_name,
        attack_type=parsed_args.attack_type,
        num_payloads=parsed_args.num_payloads,
        payloads_history=payload_history,
    )
    return {
        "waf_name": parsed_args.waf_name,
        "attack_type": parsed_args.attack_type,
        "payloads": payloads,
    }, "attack.generate-adaptive" if payload_history else "attack.generate-random"


def execute_attack_test(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    payload_data = read_json_input(parsed_args.payloads_file, parsed_args.payloads_file_id)
    payloads = extract_payload_results(payload_data)
    tested_payloads = attack._3_test_attack(
        domain=parsed_args.domain,
        payloads=payloads,
        check_harmful=not parsed_args.skip_harmful_check,
    )
    return {"payloads": tested_payloads}, "attack.test"


def execute_attack_run(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], Optional[str]]:
    detect_output = attack._1_detect_waf(parsed_args.domain)
    detect_record = save_output_file("attack.detect-waf", detect_output)

    random_payloads = attack._2_generate_payload(
        waf_name=detect_output["waf_name"],
        attack_type=parsed_args.attack_type,
        num_payloads=parsed_args.num_payloads,
    )
    generate_random_output = {
        "waf_name": detect_output["waf_name"],
        "attack_type": parsed_args.attack_type,
        "payloads": random_payloads,
    }
    generate_random_record = save_output_file("attack.generate-random", generate_random_output)

    tested_random = attack._3_test_attack(
        domain=parsed_args.domain,
        payloads=list(random_payloads),
        check_harmful=True,
    )
    test_random_output = {"payloads": tested_random}
    test_random_record = save_output_file("attack.test", test_random_output)

    adaptive_generate_output = None
    adaptive_generate_record = None
    adaptive_test_output = None
    adaptive_test_record = None
    final_payloads = list(tested_random)

    if parsed_args.adaptive:
        adaptive_payloads = attack._2_generate_payload(
            waf_name=detect_output["waf_name"],
            attack_type=parsed_args.attack_type,
            num_payloads=parsed_args.adaptive_count,
            payloads_history=list(tested_random),
        )
        adaptive_generate_output = {
            "waf_name": detect_output["waf_name"],
            "attack_type": parsed_args.attack_type,
            "payloads": adaptive_payloads,
        }
        adaptive_generate_record = save_output_file("attack.generate-adaptive", adaptive_generate_output)

        tested_adaptive = attack._3_test_attack(
            domain=parsed_args.domain,
            payloads=list(adaptive_payloads),
            check_harmful=True,
        )
        adaptive_test_output = {"payloads": tested_adaptive}
        adaptive_test_record = save_output_file("attack.test", adaptive_test_output)
        final_payloads = [*tested_random, *tested_adaptive]

    return {
        "detect_waf": detect_output,
        "saved_detect_waf": detect_record,
        "generate_random": generate_random_output,
        "saved_generate_random": generate_random_record,
        "test_random": test_random_output,
        "saved_test_random": test_random_record,
        "generate_adaptive": adaptive_generate_output,
        "saved_generate_adaptive": adaptive_generate_record,
        "test_adaptive": adaptive_test_output,
        "saved_test_adaptive": adaptive_test_record,
        "final_payloads": serialize_json(final_payloads),
    }, None


def execute_defend_clustering(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    bypassed_data = read_json_input(parsed_args.bypassed_payloads_file, parsed_args.bypassed_payloads_file_id)
    bypassed_payloads = extract_bypassed_payloads(bypassed_data)
    clusters = defend._1_clustering(
        bypassed_payloads=bypassed_payloads,
        attack_type=parsed_args.attack_type,
    )
    return {
        "attack_type": parsed_args.attack_type,
        "bypassed_payloads": bypassed_payloads,
        "clusters": clusters,
        "stats": {
            "num_bypassed_payloads": len(bypassed_payloads),
            "num_clusters": len(clusters),
        },
    }, "defend.clustering"


def execute_defend_rag(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    bypassed_data = read_json_input(parsed_args.bypassed_payloads_file, parsed_args.bypassed_payloads_file_id)
    bypassed_payloads = extract_bypassed_payloads(bypassed_data)
    rag_result, rag_sources, rag_context = defend._2_rag_retrieve(
        waf_name=parsed_args.waf_name,
        attack_type=parsed_args.attack_type,
        bypassed_payloads=bypassed_payloads,
    )
    return {
        "waf_name": parsed_args.waf_name,
        "attack_type": parsed_args.attack_type,
        "bypassed_payloads": bypassed_payloads,
        "rag_result": rag_result,
        "rag_sources": rag_sources,
        "rag_context": rag_context,
    }, "defend.rag-retrieve"


def execute_defend_generate(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    clusters_data = read_json_input(parsed_args.clusters_file, parsed_args.clusters_file_id)
    rag_context = extract_rag_context(resolve_input_path(parsed_args.rag_context_file, parsed_args.rag_context_file_id))
    clusters = extract_clusters(clusters_data)
    generated_rules, generation_prompt = defend._3_generate_rules(
        waf_name=parsed_args.waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )
    return {
        "waf_name": parsed_args.waf_name,
        "clusters": clusters,
        "rag_context": rag_context,
        "generated_rules": generated_rules,
        "generation_prompt": generation_prompt,
    }, "defend.generate-rules"


def execute_defend_validate(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    generated_rules_data = read_json_input(parsed_args.generated_rules_file, parsed_args.generated_rules_file_id)
    generated_rules = extract_rules_field(generated_rules_data, "generated_rules")
    valid_rules, invalid_rules = defend._4_validate_rules_syntax(generated_rules)
    return {
        "generated_rules": generated_rules,
        "valid_rules": valid_rules,
        "invalid_rules": invalid_rules,
    }, "defend.validate-rules"


def execute_defend_retry(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    invalid_rules_data = read_json_input(parsed_args.invalid_rules_file, parsed_args.invalid_rules_file_id)
    invalid_rules = extract_rules_field(invalid_rules_data, "invalid_rules")
    retried_rules = defend._5_retry_invalid_rules(
        waf_name=parsed_args.waf_name,
        invalid_rules=invalid_rules,
    )
    return {
        "waf_name": parsed_args.waf_name,
        "invalid_rules": invalid_rules,
        "retried_rules": retried_rules,
    }, "defend.retry-invalid-rules"


def execute_defend_refine(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    valid_rules_data = read_json_input(parsed_args.valid_rules_file, parsed_args.valid_rules_file_id)
    valid_rules = extract_rules_field(valid_rules_data, "valid_rules")
    existing_rules = load_existing_rules(parsed_args.existing_rules_file, parsed_args.existing_rules_file_id)
    final_rules = defend._6_refine_rules(
        waf_name=parsed_args.waf_name,
        valid_rules=valid_rules,
        existing_rules=existing_rules,
    )
    return {
        "waf_name": parsed_args.waf_name,
        "valid_rules": valid_rules,
        "existing_rules": existing_rules or [],
        "final_rules": final_rules,
    }, "defend.refine-rules"


def execute_defend_run(parsed_args: argparse.Namespace) -> tuple[dict[str, Any], Optional[str]]:
    bypassed_data = read_json_input(parsed_args.bypassed_payloads_file, parsed_args.bypassed_payloads_file_id)
    bypassed_payloads = extract_bypassed_payloads(bypassed_data)

    clustering_output = {
        "attack_type": parsed_args.attack_type,
        "bypassed_payloads": bypassed_payloads,
        "clusters": defend._1_clustering(
            bypassed_payloads=bypassed_payloads,
            attack_type=parsed_args.attack_type,
        ),
    }
    clustering_output["stats"] = {
        "num_bypassed_payloads": len(bypassed_payloads),
        "num_clusters": len(clustering_output["clusters"]),
    }
    clustering_record = save_output_file("defend.clustering", clustering_output)

    rag_result, rag_sources, rag_context = defend._2_rag_retrieve(
        waf_name=parsed_args.waf_name,
        attack_type=parsed_args.attack_type,
        bypassed_payloads=bypassed_payloads,
    )
    rag_output = {
        "waf_name": parsed_args.waf_name,
        "attack_type": parsed_args.attack_type,
        "bypassed_payloads": bypassed_payloads,
        "rag_result": rag_result,
        "rag_sources": rag_sources,
        "rag_context": rag_context,
    }
    rag_record = save_output_file("defend.rag-retrieve", rag_output)

    generated_rules, generation_prompt = defend._3_generate_rules(
        waf_name=parsed_args.waf_name,
        clusters=clustering_output["clusters"],
        rag_context=rag_context,
    )
    generate_output = {
        "waf_name": parsed_args.waf_name,
        "clusters": clustering_output["clusters"],
        "rag_context": rag_context,
        "generated_rules": generated_rules,
        "generation_prompt": generation_prompt,
    }
    generate_record = save_output_file("defend.generate-rules", generate_output)

    valid_rules, invalid_rules = defend._4_validate_rules_syntax(generated_rules)
    validate_output = {
        "generated_rules": generated_rules,
        "valid_rules": valid_rules,
        "invalid_rules": invalid_rules,
    }
    valid_record = save_output_file("defend.validate-valid", {"valid_rules": valid_rules})
    invalid_record = save_output_file("defend.validate-invalid", {"invalid_rules": invalid_rules})

    retried_rules = []
    if invalid_rules:
        retried_rules = defend._5_retry_invalid_rules(
            waf_name=parsed_args.waf_name,
            invalid_rules=invalid_rules,
        )
    retry_output = {
        "waf_name": parsed_args.waf_name,
        "invalid_rules": invalid_rules,
        "retried_rules": retried_rules,
    }
    retry_record = save_output_file("defend.retry-invalid-rules", retry_output)

    final_input_rules = [*valid_rules, *retried_rules]
    existing_rules = load_existing_rules(parsed_args.existing_rules_file, parsed_args.existing_rules_file_id)
    final_rules = defend._6_refine_rules(
        waf_name=parsed_args.waf_name,
        valid_rules=final_input_rules,
        existing_rules=existing_rules,
    )
    refine_output = {
        "waf_name": parsed_args.waf_name,
        "valid_rules": final_input_rules,
        "existing_rules": existing_rules or [],
        "final_rules": final_rules,
    }
    refine_record = save_output_file("defend.refine-rules", refine_output)

    return {
        "clustering": clustering_output,
        "saved_clustering": clustering_record,
        "rag_retrieve": rag_output,
        "saved_rag_retrieve": rag_record,
        "generate_rules": generate_output,
        "saved_generate_rules": generate_record,
        "validate_rules": validate_output,
        "saved_valid_rules": valid_record,
        "saved_invalid_rules": invalid_record,
        "retry_invalid_rules": retry_output,
        "saved_retry_invalid_rules": retry_record,
        "refine_rules": refine_output,
        "saved_refine_rules": refine_record,
    }, None


def execute_outputs_list(parsed_args: argparse.Namespace) -> None:
    index_data = load_output_index()
    items = index_data.get("items", [])
    if parsed_args.type:
        items = [item for item in items if item.get("output_type") == parsed_args.type]

    def sort_key(item: dict[str, Any]) -> tuple[str, int, str]:
        file_id = str(item.get("id", ""))
        match = re.fullmatch(r"([a-z]+)(\d+)", file_id)
        if not match:
            return (str(item.get("output_type", "")), 10**9, file_id)
        return (match.group(1), int(match.group(2)), file_id)

    print(json.dumps(sorted(items, key=sort_key), indent=2))


def execute_outputs_remove(parsed_args: argparse.Namespace) -> None:
    index_data = load_output_index()
    remaining_items = []
    removed_record = None
    for item in index_data.get("items", []):
        if item.get("id") == parsed_args.id:
            removed_record = item
        else:
            remaining_items.append(item)

    if removed_record is None:
        raise ValueError(f"Unknown file id: {parsed_args.id}")

    file_path = REPO_ROOT / Path(removed_record["path"])
    if file_path.exists():
        file_path.unlink()

    index_data["items"] = remaining_items
    save_output_index(index_data)
    print(json.dumps({"removed": removed_record}, indent=2))


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = list(argv if argv is not None else sys.argv[1:])

    if not args:
        print_cli_help(parser)
        return 0

    parsed_args = parser.parse_args(args)

    try:
        if parsed_args.pipeline == "attack":
            if parsed_args.attack_command == "detect-waf":
                output, output_type = execute_attack_detect(parsed_args)
            elif parsed_args.attack_command == "generate-payload":
                output, output_type = execute_attack_generate(parsed_args)
            elif parsed_args.attack_command == "test":
                output, output_type = execute_attack_test(parsed_args)
            elif parsed_args.attack_command == "run":
                output, output_type = execute_attack_run(parsed_args)
            else:
                raise ValueError("Missing attack subcommand")

            if output_type is None:
                print(json.dumps(serialize_json(output), indent=2))
                return 0

            record = save_output_file(output_type, output)
            print_saved_output(record, output)
            return 0

        if parsed_args.pipeline == "defend":
            if parsed_args.defend_command == "clustering":
                output, output_type = execute_defend_clustering(parsed_args)
            elif parsed_args.defend_command == "rag-retrieve":
                output, output_type = execute_defend_rag(parsed_args)
            elif parsed_args.defend_command == "generate-rules":
                output, output_type = execute_defend_generate(parsed_args)
            elif parsed_args.defend_command == "validate-rules":
                output, _ = execute_defend_validate(parsed_args)
                valid_record = save_output_file("defend.validate-valid", {"valid_rules": output["valid_rules"]})
                invalid_record = save_output_file("defend.validate-invalid", {"invalid_rules": output["invalid_rules"]})
                print(json.dumps({
                    "saved_valid_rules": valid_record,
                    "saved_invalid_rules": invalid_record,
                    "output": serialize_json(output),
                }, indent=2))
                return 0
            elif parsed_args.defend_command == "retry-invalid-rules":
                output, output_type = execute_defend_retry(parsed_args)
            elif parsed_args.defend_command == "refine-rules":
                output, output_type = execute_defend_refine(parsed_args)
            elif parsed_args.defend_command == "run":
                output, output_type = execute_defend_run(parsed_args)
            else:
                raise ValueError("Missing defend subcommand")

            if output_type is None:
                print(json.dumps(serialize_json(output), indent=2))
                return 0

            record = save_output_file(output_type, output)
            print_saved_output(record, output)
            return 0

        if parsed_args.pipeline == "outputs":
            if parsed_args.outputs_command == "list":
                execute_outputs_list(parsed_args)
                return 0
            if parsed_args.outputs_command == "remove":
                execute_outputs_remove(parsed_args)
                return 0
            raise ValueError("Missing outputs subcommand")

        raise ValueError("Missing pipeline command")
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())