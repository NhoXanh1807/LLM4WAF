import json
import sys
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any
import modules.file_manager as file_manager
from modules.classes import OutputType
from models.dtos import PayloadResult


def _serialize_json(data: Any) -> Any:
    if is_dataclass(data):
        return {key: _serialize_json(value) for key, value in asdict(data).items()}
    if isinstance(data, Enum):
        return data.value
    if isinstance(data, dict):
        return {str(key): _serialize_json(value) for key, value in data.items()}
    if isinstance(data, (list, tuple)):
        return [_serialize_json(value) for value in data]
    return data


def handle_exit():
    print("Exiting...")
    sys.exit(0)

def handle_files_all():
    files = file_manager.list_files()
    print("="*10 + " Files " + "="*10)
    if not files:
        print("No files found.")
    for file in files:
        print(f"{file.name} -> {file.path}")
    print("="*30)

def handle_files_view(file_id: str):
    content = file_manager.read_file(file_id)
    if content is None:
        raise ValueError(f"Unknown file id: {file_id}")
    data = json.loads(content)
    if OutputType.GENPAYLOAD.value in file_id:
        for i, item in enumerate(data):
            print(f"#{i+1} - {item['attack_type']} - {item['technique']}")
            print(f"\t{item['payload']}")
    elif OutputType.TEST.value in file_id:
        for i, item in enumerate(data):
            print(f"#{i+1} - {item['attack_type']} - {item['technique']}")
            print(f"\t{item['payload']}")
            print(f"\t\tBypassed: {item['is_bypassed']}, Harmful: {item['is_harmful']}")
        
        bypassed = sum(1 for item in data if item["is_bypassed"])
        harmful = sum(1 for item in data if item["is_harmful"])
        bypassed_and_harmful = sum(1 for item in data if item["is_bypassed"] and item["is_harmful"])
        bypassed_not_harmful = sum(1 for item in data if item["is_bypassed"] and not item["is_harmful"])
        not_bypassed_harmful = sum(1 for item in data if not item["is_bypassed"] and item["is_harmful"])
        not_bypassed_not_harmful = sum(1 for item in data if not item["is_bypassed"] and not item["is_harmful"])
        print()
        print(f"Bypassed: {bypassed}/{len(data)}, Harmful: {harmful}/{len(data)}")
        print(f"Bypassed and Harmful: {bypassed_and_harmful}, Bypassed not Harmful: {bypassed_not_harmful}")
        print(f"Not Bypassed and Harmful: {not_bypassed_harmful}, Not Bypassed not Harmful: {not_bypassed_not_harmful}")
    
    elif OutputType.CLUSTER.value in file_id:
        data = sorted(data, key=lambda x: x["cluster_id"], reverse=False)
        for cluster in data:
            print(f"#{cluster['cluster_id']} - {len(cluster.get('payloads', []))} payloads:")
            for payload in cluster.get("payloads", []):
                print(f"\t{payload}")
    elif OutputType.RAG.value in file_id:
        print(f"WAF: {data.get('waf_name', '')}, Attack Type: {data.get('attack_type', '')}")
        print("RAG Queries:")
        for query in data["rag_result"]["queries"]:
            print(f"\t{query}")
        print("Retrieved Sources:")
        for source in data["rag_result"]["sources"]:
            print(f"\t[{source['source']}]")
            print("\t\t" + source["content"].replace("\n", "\n\t\t"))
    elif OutputType.GENRULE.value in file_id:
        for i, item in enumerate(data.get("generated_rules", [])):
            print(f"Rule #{i+1} - Instructions: {item.get('instructions', '')}")
            print(f"\t{item.get('rule', '')}")
    elif OutputType.VALIDRULE.value in file_id or OutputType.INVALIDRULE.value in file_id or OutputType.FIXEDRULE.value in file_id:
        for i, item in enumerate(data):
            print(f"Rule #{i+1} - Instructions: {item.get('instructions', '')}")
            print(f"\t{item.get('rule', '')}")
            if "validation_error" in item:
                print(f"\tValidation Error: {item['validation_error']}")
    elif OutputType.FINALRULE.value in file_id:
        for i, item in enumerate(data):
            print(f"Rule #{i+1} - Instructions: {item.get('instructions', '')}")
            print(f"\t{item.get('rule', '')}")

def handle_files_remove(file_id: str):
    removed = file_manager.remove_file(file_id)
    if not removed:
        raise ValueError(f"Unknown file id: {file_id}")
    print(json.dumps({"removed": file_id}, indent=2))

def handle_attack_detect(domain: str):
    import attack_pipeline
    result = attack_pipeline._1_detect_waf(domain)
    

def handle_attack_generate(waf_name: str, attack_type: str, num: str, tested_file: str | None = None):
    payload_history = []
    if tested_file:
        if OutputType.TEST.value not in tested_file:
            raise ValueError("Tested file must be a test output file")
        content = file_manager.read_file(tested_file)
        if content is None:
            raise ValueError(f"Unknown file id: {tested_file}")
        data = json.loads(content)
        raw_payloads = data.get("payloads") if isinstance(data, dict) else data
        if not isinstance(raw_payloads, list):
            raise ValueError("Payload input must be a JSON list or an object with a 'payloads' field")
        payload_history = [
            PayloadResult(
                payload=str(item.get("payload", "")),
                technique=str(item.get("technique", "")),
                attack_type=str(item.get("attack_type", "")),
                status_code=item.get("status_code"),
                is_bypassed=item.get("is_bypassed"),
                is_harmful=item.get("is_harmful"),
            )
            for item in raw_payloads
            if isinstance(item, dict)
        ]
    import attack_pipeline
    payloads = attack_pipeline._2_generate_payload(
        waf_name=waf_name,
        attack_type=attack_type,
        num_payloads=int(num),
        payloads_history=payload_history,
    )
    serialized_payloads = _serialize_json(payloads)
    file = file_manager.save_file(OutputType.GENPAYLOAD, serialized_payloads)
    print(f"Saved output to file: {file.name} -> {file.path}")
    

def handle_attack_test(domain: str, generate_file: str):
    if OutputType.GENPAYLOAD.value not in generate_file:
        raise ValueError("Generate file must be a generated payload output file")
    content = file_manager.read_file(generate_file)
    if content is None:
        raise ValueError(f"Unknown file id: {generate_file}")
    data = json.loads(content)
    raw_payloads = data.get("payloads") if isinstance(data, dict) else data
    if not isinstance(raw_payloads, list):
        raise ValueError("Payload input must be a JSON list or an object with a 'payloads' field")
    payloads = [
        PayloadResult(
            payload=str(item.get("payload", "")),
            technique=str(item.get("technique", "")),
            attack_type=str(item.get("attack_type", "")),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in raw_payloads
        if isinstance(item, dict)
    ]
    import attack_pipeline
    tested_payloads = attack_pipeline._3_test_attack(
        domain=domain,
        payloads=payloads,
    )
    serialized_payloads = _serialize_json(tested_payloads)
    file = file_manager.save_file(OutputType.TEST, serialized_payloads)
    print(f"Saved output to file: {file.name} -> {file.path}")

def handle_defend_cluster(bypassed_file: str):
    if OutputType.TEST.value not in bypassed_file:
        raise ValueError("Bypassed file must be a test output file")
    content = file_manager.read_file(bypassed_file)
    if content is None:
        raise ValueError(f"Unknown file id: {bypassed_file}")
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("Bypassed input must be a JSON list from attack test output")
    bypassed_payloads = [
        str(item.get("payload", "")).strip()
        for item in data
        if isinstance(item, dict) and item.get("is_bypassed") and item.get("is_harmful") and str(item.get("payload", "")).strip()
    ]
    import defend_pipeline
    clusters = defend_pipeline._1_clustering(bypassed_payloads=bypassed_payloads)
    serialized_clusters = _serialize_json(clusters)
    file = file_manager.save_file(OutputType.CLUSTER, serialized_clusters)
    print(f"Saved output to file: {file.name} -> {file.path}")


def handle_defend_rag(waf_name: str, attack_type: str, bypassed_file: str):
    if OutputType.TEST.value not in bypassed_file:
        raise ValueError("Bypassed file must be a test output file")
    content = file_manager.read_file(bypassed_file)
    if content is None:
        raise ValueError(f"Unknown file id: {bypassed_file}")
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("Bypassed input must be a JSON list from attack test output")
    bypassed_payloads = [
        str(item.get("payload", "")).strip()
        for item in data
        if isinstance(item, dict) and item.get("is_bypassed") and item.get("is_harmful") and str(item.get("payload", "")).strip()
    ]
    import defend_pipeline
    rag_result, rag_sources, rag_context = defend_pipeline._2_rag_retrieve(
        waf_name=waf_name,
        attack_type=attack_type,
        bypassed_payloads=bypassed_payloads,
    )
    rag_output = _serialize_json({
        "waf_name": waf_name,
        "attack_type": attack_type,
        "bypassed_payloads": bypassed_payloads,
        "rag_result": rag_result,
        "rag_sources": rag_sources,
        "rag_context": rag_context,
    })
    file = file_manager.save_file(OutputType.RAG, rag_output)
    print(f"Saved output to file: {file.name} -> {file.path}")


def handle_defend_genrule(waf_name: str, cluster_file: str, rag_file: str | None = None):
    if OutputType.CLUSTER.value not in cluster_file:
        raise ValueError("Cluster file must be a cluster output file")
    cluster_content = file_manager.read_file(cluster_file)
    if cluster_content is None:
        raise ValueError(f"Unknown file id: {cluster_file}")
    cluster_data = json.loads(cluster_content)
    clusters = [item for item in cluster_data if isinstance(item, dict)]
    rag_context = ""
    if rag_file:
        if OutputType.RAG.value not in rag_file:
            raise ValueError("RAG file must be a RAG output file")
        rag_content = file_manager.read_file(rag_file)
        if rag_content is None:
            raise ValueError(f"Unknown file id: {rag_file}")
        rag_data = json.loads(rag_content)
        rag_context = rag_data.get("rag_context", "") if isinstance(rag_data, dict) else ""
    import defend_pipeline
    generated_rules, generation_prompt = defend_pipeline._3_generate_rules(
        waf_name=waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )
    genrule_output = _serialize_json({
        "generated_rules": generated_rules,
        "generation_prompt": generation_prompt,
    })
    file = file_manager.save_file(OutputType.GENRULE, genrule_output)
    print(f"Saved output to file: {file.name} -> {file.path}")


def handle_defend_validate(genrule_file: str):
    if OutputType.GENRULE.value not in genrule_file:
        raise ValueError("Genrule file must be a genrule output file")
    content = file_manager.read_file(genrule_file)
    if content is None:
        raise ValueError(f"Unknown file id: {genrule_file}")
    data = json.loads(content)
    if not isinstance(data, dict) or not isinstance(data.get("generated_rules"), list):
        raise ValueError("Expected 'generated_rules' as a JSON list")
    generated_rules = [item for item in data["generated_rules"] if isinstance(item, dict)]
    import defend_pipeline
    valid_rules, invalid_rules = defend_pipeline._4_validate_rules_syntax(generated_rules)
    if len(valid_rules) > 0:
        valid_output = _serialize_json(valid_rules)
        valid_file = file_manager.save_file(OutputType.VALIDRULE, valid_output)
        print(f"Saved output to file: {valid_file.output_type.value}{valid_file.id} -> {valid_file.path}")
    if len(invalid_rules) > 0:
        invalid_output = _serialize_json(invalid_rules)
        invalid_file = file_manager.save_file(OutputType.INVALIDRULE, invalid_output)
        print(f"Saved output to file: {invalid_file.output_type.value}{invalid_file.id} -> {invalid_file.path}")


def handle_defend_retry(waf_name: str, invalidrule_file: str):
    if OutputType.INVALIDRULE.value not in invalidrule_file:
        raise ValueError("Invalid rule file must be an invalid rule output file")
    content = file_manager.read_file(invalidrule_file)
    if content is None:
        raise ValueError(f"Unknown file id: {invalidrule_file}")
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("Invalid rule input must be a JSON list")
    invalid_rules = [item for item in data if isinstance(item, dict)]
    import defend_pipeline
    fixed_rules = defend_pipeline._5_retry_invalid_rules(
        waf_name=waf_name,
        invalid_rules=invalid_rules,
    )
    fixed_output = _serialize_json(fixed_rules)
    file = file_manager.save_file(OutputType.FIXEDRULE, fixed_output)
    print(f"Saved output to file: {file.name} -> {file.path}")


def handle_defend_refine(waf_name: str, validrule_file: str, fixedrule_file: str | None = None, existing_rule_file_path: str | None = None):
    if OutputType.VALIDRULE.value not in validrule_file:
        raise ValueError("Valid rule file must be a valid rule output file")
    valid_content = file_manager.read_file(validrule_file)
    if valid_content is None:
        raise ValueError(f"Unknown file id: {validrule_file}")
    valid_data = json.loads(valid_content)
    if not isinstance(valid_data, list):
        raise ValueError("Valid rule input must be a JSON list")
    valid_rules = [item for item in valid_data if isinstance(item, dict)]
    if fixedrule_file:
        if OutputType.FIXEDRULE.value not in fixedrule_file:
            raise ValueError("Fixed rule file must be a fixed rule output file")
        fixed_content = file_manager.read_file(fixedrule_file)
        if fixed_content is None:
            raise ValueError(f"Unknown file id: {fixedrule_file}")
        fixed_data = json.loads(fixed_content)
        if not isinstance(fixed_data, list):
            raise ValueError("Fixed rule input must be a JSON list")
        valid_rules = [
            *valid_rules,
            *[item for item in fixed_data if isinstance(item, dict)],
        ]
    import defend_pipeline
    if existing_rule_file_path:
        print(f"[Auto] Loading existing rules from: {existing_rule_file_path}")
        with open(existing_rule_file_path, "r", encoding="utf-8") as f:
            existing_rules_lines = f.readlines()
        existing_rules = defend_pipeline._parse_existing_rules(existing_rules_lines)
        print(f"[Auto] Loaded {len(existing_rules)} existing rules for refinement.")
    else:
        existing_rules = None
    final_rules = defend_pipeline._6_refine_rules(
        waf_name=waf_name,
        valid_rules=valid_rules,
        existing_rules=existing_rules,
    )
    final_output = _serialize_json(final_rules)
    file = file_manager.save_file(OutputType.FINALRULE, final_output)
    print(f"Saved output to file: {file.name} -> {file.path}")

def handle_attack_auto(domain: str, attack_type: str, num: str, num_adaptive: str):
    import attack_pipeline

    # 1. Detect WAF
    detected_data = attack_pipeline._1_detect_waf(domain)
    
    # 2. Generate payload
    payloads = attack_pipeline._2_generate_payload(
        waf_name=detected_data.get("waf_name"),
        attack_type=attack_type,
        num_payloads=int(num),
        payloads_history=[],
    )
    serialized_payloads = _serialize_json(payloads)
    gen_file = file_manager.save_file(OutputType.GENPAYLOAD, serialized_payloads)
    print(f"[Auto] Saved generated payloads: {gen_file.name} -> {gen_file.path}")
    
    # 3. Test payload
    tested_payloads = attack_pipeline._3_test_attack(
        domain=domain,
        payloads=payloads,
    )
    serialized_tested = _serialize_json(tested_payloads)
    test_file = file_manager.save_file(OutputType.TEST, serialized_tested)
    print(f"[Auto] Saved test results: {test_file.name} -> {test_file.path}")
    
    if num_adaptive and int(num_adaptive) > 0:
        # 4. Adaptive generate
        adaptive_payloads = attack_pipeline._2_generate_payload(
            waf_name=detected_data.get("waf_name"),
            attack_type=attack_type,
            num_payloads=int(num_adaptive),
            payloads_history=tested_payloads,
        )
        serialized_adaptive = _serialize_json(adaptive_payloads)
        adaptive_file = file_manager.save_file(OutputType.GENPAYLOAD, serialized_adaptive)
        print(f"[Auto] Saved adaptive generated payloads: {adaptive_file.name} -> {adaptive_file.path}")
        
        # 5. Test adaptive payload
        tested_adaptive_payloads = attack_pipeline._3_test_attack(
            domain=domain,
            payloads=adaptive_payloads,
        )
        serialized_adaptive_tested = _serialize_json(tested_adaptive_payloads)
        test_adaptive_file = file_manager.save_file(OutputType.TEST, serialized_adaptive_tested)
        print(f"[Auto] Saved test adaptive results: {test_adaptive_file.name} -> {test_adaptive_file.path}")

        # 6. Save combined tested results
        combined_tested_payloads = tested_payloads + tested_adaptive_payloads
        serialized_combined_tested = _serialize_json(combined_tested_payloads)
        combined_test_file = file_manager.save_file(OutputType.TEST, serialized_combined_tested)
        print(f"[Auto] Saved combined RANDOM + ADAPTIVE test results: {combined_test_file.name} -> {combined_test_file.path}")


def handle_defend_auto(waf_name: str, attack_type: str, bypassed_file: str, existing_rule_file_path: str | None = None):
    import defend_pipeline

    content = file_manager.read_file(bypassed_file)
    if content is None:
        raise ValueError(f"Unknown file: {bypassed_file}")
    data = json.loads(content)
    bypassed_payloads = [
        str(item.get("payload", "")).strip()
        for item in data
        if isinstance(item, dict) and item.get("is_bypassed") and item.get("is_harmful") and str(item.get("payload", "")).strip()
    ]
    
    # 1. Cluster
    clusters = defend_pipeline._1_clustering(bypassed_payloads=bypassed_payloads)
    serialized_clusters = _serialize_json(clusters)
    cluster_file = file_manager.save_file(OutputType.CLUSTER, serialized_clusters)
    print(f"[Auto] Saved clusters: {cluster_file.name} -> {cluster_file.path}")
    
    # 2. RAG
    rag_result, rag_sources, rag_context = defend_pipeline._2_rag_retrieve(
        waf_name=waf_name,
        attack_type=attack_type,
        bypassed_payloads=bypassed_payloads,
    )
    rag_output = _serialize_json({
        "waf_name": waf_name,
        "attack_type": attack_type,
        "bypassed_payloads": bypassed_payloads,
        "rag_result": rag_result,
        "rag_sources": rag_sources,
        "rag_context": rag_context,
    })
    rag_file = file_manager.save_file(OutputType.RAG, rag_output)
    print(f"[Auto] Saved RAG: {rag_file.name} -> {rag_file.path}")
    
    
    # 3. Genrule
    generated_rules, generation_prompt = defend_pipeline._3_generate_rules(
        waf_name=waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )
    genrule_output = _serialize_json({
        "generated_rules": generated_rules,
        "generation_prompt": generation_prompt,
    })
    genrule_file = file_manager.save_file(OutputType.GENRULE, genrule_output)
    print(f"[Auto] Saved generated rules: {genrule_file.name} -> {genrule_file.path}")
    
    
    # 4. Validate
    valid_rules, invalid_rules = defend_pipeline._4_validate_rules_syntax(generated_rules)
    if valid_rules:
        valid_output = _serialize_json(valid_rules)
        valid_file = file_manager.save_file(OutputType.VALIDRULE, valid_output)
        print(f"[Auto] Saved valid rules: {valid_file.name} -> {valid_file.path}")
    if invalid_rules:
        invalid_output = _serialize_json(invalid_rules)
        invalid_file = file_manager.save_file(OutputType.INVALIDRULE, invalid_output)
        print(f"[Auto] Saved invalid rules: {invalid_file.name} -> {invalid_file.path}")
    
    
    # 5. Retry nếu có invalid
    all_valid_rules = valid_rules[:]
    if invalid_rules:
        fixed_rules = defend_pipeline._5_retry_invalid_rules(
            waf_name=waf_name,
            invalid_rules=invalid_rules,
        )
        fixed_output = _serialize_json(fixed_rules)
        fixed_file = file_manager.save_file(OutputType.FIXEDRULE, fixed_output)
        print(f"[Auto] Saved fixed rules: {fixed_file.name} -> {fixed_file.path}")
        all_valid_rules.extend(fixed_rules)
    
    
    # 6. Refine
    if existing_rule_file_path:
        print(f"[Auto] Loading existing rules from: {existing_rule_file_path}")
        with open(existing_rule_file_path, "r", encoding="utf-8") as f:
            existing_rules_lines = f.readlines()
        existing_rules = defend_pipeline._parse_existing_rules(existing_rules_lines)
        print(f"[Auto] Loaded {len(existing_rules)} existing rules for refinement.")
    else:
        existing_rules = None
    final_rules = defend_pipeline._6_refine_rules(
        waf_name=waf_name,
        valid_rules=all_valid_rules,
        existing_rules=existing_rules,
    )
    final_output = _serialize_json(final_rules)
    final_file = file_manager.save_file(OutputType.FINALRULE, final_output)
    print(f"[Auto] Saved final rules: {final_file.name} -> {final_file.path}")
    print("[Auto] Defend pipeline completed.")
