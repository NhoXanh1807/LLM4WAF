import msc_pyparser
import json
import glob
import os
import yaml
from collections import defaultdict

# Đường dẫn
rules_dir = "coreruleset/rules"
tests_dir = "coreruleset/tests/regression/tests"
output_dir = "parsed_output"
training_dir = "training_data"
manual_dir = "manual_testing_needed"

os.makedirs(output_dir, exist_ok=True)
os.makedirs(training_dir, exist_ok=True)
os.makedirs(manual_dir, exist_ok=True)

def save_jsonl(data, filename):
    """Lưu dữ liệu dạng JSONL (mỗi dòng 1 JSON object)"""
    with open(filename, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')

def extract_metadata(actions):
    """Trích xuất metadata từ actions"""
    metadata = {}
    for action in actions:
        if action['act_name'] == 'msg':
            metadata['message'] = action['act_arg']
        elif action['act_name'] == 'logdata':
            metadata['logdata'] = action['act_arg']
        elif action['act_name'] == 'ver':
            metadata['version'] = action['act_arg']
        elif action['act_name'] == 'phase':
            metadata['phase'] = action['act_arg']
    return metadata

def extract_attack_type(actions):
    """Trích xuất loại attack từ tags"""
    attack_tags = [
        action['act_arg'] 
        for action in actions 
        if action['act_name'] == 'tag' and 'attack-' in action['act_arg']
    ]
    return attack_tags

def extract_severity(actions):
    """Trích xuất severity"""
    for action in actions:
        if action['act_name'] == 'severity':
            return action['act_arg']
    return None

def extract_tags(actions):
    """Trích xuất tất cả tags"""
    return [
        action['act_arg'] 
        for action in actions 
        if action['act_name'] == 'tag'
    ]

def extract_malicious_patterns(stage):
    """Trích xuất các pattern độc hại từ test"""
    patterns = []
    
    # Từ URI
    uri = stage['input'].get('uri', '')
    if '?' in uri:
        patterns.append({
            'location': 'uri_params',
            'value': uri.split('?', 1)[1]
        })
    
    # Từ data (POST body)
    data = stage['input'].get('data', '')
    if data:
        patterns.append({
            'location': 'post_body',
            'value': data
        })
    
    # Từ headers
    for header, value in stage['input'].get('headers', {}).items():
        if header.lower() in ['user-agent', 'referer'] and len(value) > 50:
            patterns.append({
                'location': f'header_{header.lower()}',
                'value': value
            })
    
    return patterns

def extract_test_cases(tests):
    """Trích xuất test cases thành format đơn giản"""
    if not tests or 'tests' not in tests:
        return []
    
    simplified_tests = []
    for test in tests['tests']:
        for stage in test.get('stages', []):
            output = stage.get('output', {})
            log_data = output.get('log', {})
            
            has_expect_ids = 'expect_ids' in log_data
            
            test_case = {
                "description": test.get('desc', ''),
                "test_id": test.get('test_id'),
                "request": {
                    "method": stage['input'].get('method'),
                    "uri": stage['input'].get('uri'),
                    "headers": stage['input'].get('headers', {}),
                    "data": stage['input'].get('data', '')
                },
                "expected": {
                    "should_block": has_expect_ids,
                    "rule_ids": log_data.get('expect_ids', log_data.get('no_expect_ids', []))
                },
                "malicious_patterns": extract_malicious_patterns(stage)
            }
            simplified_tests.append(test_case)
    
    return simplified_tests

def normalize_rule_for_training(rule_data):
    """Chuẩn hóa rule sang format dễ học cho AI"""
    rule = rule_data['rule']
    
    try:
        normalized = {
            "rule_id": rule_data['rule_id'],
            "has_tests": rule_data['tests'] is not None,
            "detection": {
                "variables": [
                    {
                        "name": v.get('variable', ''),
                        "part": v.get('variable_part', ''),
                        "negated": v.get('negated', False)
                    }
                    for v in rule.get('variables', [])
                ],
                "operator": {
                    "type": rule.get('operator', ''),
                    "argument": rule.get('operator_argument', ''),
                    "negated": rule.get('operator_negated', False)
                }
            },
            "transformations": [
                action.get('act_arg', '') 
                for action in rule.get('actions', []) 
                if action.get('act_name') == 't'
            ],
            "metadata": extract_metadata(rule.get('actions', [])),
            "attack_info": {
                "type": extract_attack_type(rule.get('actions', [])),
                "severity": extract_severity(rule.get('actions', [])),
                "tags": extract_tags(rule.get('actions', []))
            },
            "test_cases": extract_test_cases(rule_data.get('tests')),
            "raw_rule": rule
        }
        return normalized
    except Exception as e:
        print(f"    ⚠️  Error normalizing rule {rule_data.get('rule_id')}: {e}")
        return {
            "rule_id": rule_data['rule_id'],
            "has_tests": False,
            "detection": {},
            "transformations": [],
            "metadata": {},
            "attack_info": {"type": [], "severity": None, "tags": []},
            "test_cases": [],
            "raw_rule": rule
        }

def create_training_sample(rule, test_case):
    """Tạo 1 training sample từ rule và test case"""
    return {
        "input": {
            "malicious_payload": test_case['malicious_patterns'],
            "attack_context": {
                "method": test_case['request']['method'],
                "location": [p['location'] for p in test_case['malicious_patterns']]
            }
        },
        "output": {
            "detection": rule['detection'],
            "transformations": rule['transformations'],
            "attack_type": rule['attack_info']['type'],
            "severity": rule['attack_info']['severity']
        },
        "metadata": {
            "rule_id": rule['rule_id'],
            "test_description": test_case['description']
        }
    }

def create_manual_test_template(rule):
    """Tạo template YAML để manual viết test"""
    return {
        "meta": {
            "author": "YOUR_NAME",
            "description": f"Tests for rule {rule['rule_id']}"
        },
        "rule_id": int(rule['rule_id']) if rule['rule_id'] and rule['rule_id'].isdigit() else 0,
        "tests": [
            {
                "test_id": 1,
                "desc": "TODO: Describe what this test is checking",
                "stages": [
                    {
                        "input": {
                            "dest_addr": "127.0.0.1",
                            "method": "GET",
                            "port": 80,
                            "uri": "/test?param=MALICIOUS_PAYLOAD_HERE",
                            "headers": {
                                "User-Agent": "OWASP CRS test agent",
                                "Host": "localhost"
                            },
                            "data": "",
                            "version": "HTTP/1.1"
                        },
                        "output": {
                            "log": {
                                "expect_ids": [int(rule['rule_id'])] if rule['rule_id'] and rule['rule_id'].isdigit() else []
                            }
                        }
                    }
                ]
            }
        ],
        "rule_info": {
            "message": rule['metadata'].get('message', ''),
            "attack_type": rule['attack_info']['type'],
            "severity": rule['attack_info']['severity'],
            "variables": [v['name'] for v in rule['detection']['variables']],
            "operator": rule['detection']['operator']['type']
        }
    }

def load_test_data(conf_basename):
    """Load test data từ folder tương ứng"""
    test_folder_name = conf_basename.replace('.conf', '')
    test_folder_path = os.path.join(tests_dir, test_folder_name)
    
    test_data = {}
    
    if not os.path.exists(test_folder_path):
        return test_data
    
    yaml_files = glob.glob(f"{test_folder_path}/*.yaml")
    
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                yaml_content = yaml.safe_load(f)
                
                if not yaml_content:
                    continue
                
                rule_id = os.path.basename(yaml_file).replace('.yaml', '')
                test_data[rule_id] = yaml_content
                
        except Exception as e:
            pass
    
    return test_data

def is_xss_or_sqli_file(filename):
    """Check if file is XSS or SQLi"""
    upper_name = filename.upper()
    return 'XSS' in upper_name or 'SQL' in upper_name

def main():
    """Hàm chính xử lý toàn bộ pipeline"""
    
    print("🔄 Processing ALL rules...\n")
    
    rule_files = glob.glob(f"{rules_dir}/*.conf")
    
    all_normalized_rules = []
    training_samples = []
    rules_without_tests_xss_sqli = []
    
    total_rules = 0
    total_with_tests = 0
    total_without_tests = 0
    
    # ✅ DEBUG: Track missing tests
    debug_missing_tests = defaultdict(list)
    
    for rule_file in rule_files:
        try:
            conf_basename = os.path.basename(rule_file)
            print(f"📄 {conf_basename}")
            
            # Parse rule file
            with open(rule_file, 'r') as f:
                content = f.read()

            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(content)

            clean_rules = [
                item for item in mparser.configlines
                if item.get('type') == 'SecRule'
            ]

            if not clean_rules:
                print(f"  ⚠ Skipped (No SecRules)\n")
                continue

            # Load tests
            test_data = load_test_data(conf_basename)
            
            is_target_file = is_xss_or_sqli_file(conf_basename)
            
            rules_with_tests_count = 0
            rules_without_tests_count = 0
            
            rules_with_tests = []
            for rule in clean_rules:
                rule_id = None
                actions = rule.get('actions', [])
                
                for action in actions:
                    if action.get('act_name') == 'id':
                        rule_id = action.get('act_arg', '')
                        break
                
                rule_data = {
                    'rule': rule,
                    'rule_id': rule_id,
                    'tests': test_data.get(rule_id) if rule_id else None
                }
                
                normalized = normalize_rule_for_training(rule_data)
                all_normalized_rules.append(normalized)
                rules_with_tests.append(rule_data)
                
                total_rules += 1
                
                if normalized['has_tests'] and normalized['test_cases']:
                    rules_with_tests_count += 1
                    total_with_tests += 1
                    
                    for test_case in normalized['test_cases']:
                        if test_case.get('malicious_patterns'):
                            try:
                                sample = create_training_sample(normalized, test_case)
                                training_samples.append(sample)
                            except Exception as e:
                                pass
                else:
                    rules_without_tests_count += 1
                    total_without_tests += 1
                    
                    # ✅ DEBUG: Track missing
                    if is_target_file:
                        debug_missing_tests[conf_basename].append(rule_id)
                        
                        # ✅ CHỈ TẠO YAML CHO RULE_ID HỢP LỆ
                        if rule_id and rule_id.strip() and rule_id.isdigit():
                            rules_without_tests_xss_sqli.append({
                                "file": conf_basename,
                                "rule_id": rule_id,
                                "rule": normalized,
                                "yaml_template": create_manual_test_template(normalized)
                            })
                        else:
                            print(f"    ⚠️  Skipped invalid rule_id: '{rule_id}'")

            output_file = os.path.join(output_dir, conf_basename.replace('.conf', '.json'))
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(rules_with_tests, f, indent=2, ensure_ascii=False)

            print(f"  ✅ With tests: {rules_with_tests_count}")
            print(f"  ⚠️  Without tests: {rules_without_tests_count}")
            
            # ✅ Show missing rule IDs for XSS/SQLi
            if is_target_file and rules_without_tests_count > 0:
                missing_ids = [rid for rid in debug_missing_tests[conf_basename] if rid]
                print(f"  🔍 Missing test IDs: {', '.join(missing_ids[:10])}")
                if len(missing_ids) > 10:
                    print(f"      ... and {len(missing_ids) - 10} more")
            print()

        except Exception as e:
            print(f"  ✗ Error processing {os.path.basename(rule_file)}: {e}\n")

    # === LƯU RULES THIẾU TEST ===
    if rules_without_tests_xss_sqli:
        print("\n📝 Saving XSS/SQLi rules without tests...")
        
        grouped_by_file = defaultdict(list)
        for item in rules_without_tests_xss_sqli:
            grouped_by_file[item['file']].append(item)
        
        for filename, rules in grouped_by_file.items():
            output_name = filename.replace('.conf', '_NEED_TESTS.json')
            output_path = os.path.join(manual_dir, output_name)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            
            print(f"  📄 {output_name}: {len(rules)} rules")
            
            # ✅ List rule IDs being saved
            rule_ids = [r['rule_id'] for r in rules if r['rule_id']]
            print(f"      Rule IDs: {', '.join(rule_ids)}")
            
            yaml_dir = os.path.join(manual_dir, "yaml_templates", filename.replace('.conf', ''))
            os.makedirs(yaml_dir, exist_ok=True)
            
            yaml_created = 0
            for rule_item in rules:
                if rule_item['rule_id']:
                    yaml_file = os.path.join(yaml_dir, f"{rule_item['rule_id']}.yaml")
                    with open(yaml_file, 'w', encoding='utf-8') as f:
                        yaml.dump(rule_item['yaml_template'], f, 
                                 default_flow_style=False, 
                                 allow_unicode=True,
                                 sort_keys=False)
                    yaml_created += 1
            
            print(f"      ✅ Created {yaml_created} YAML templates\n")

    # === TẠO TRAINING FILES ===
    print("\n🤖 Creating AI training files...")
    
    normalized_file = os.path.join(training_dir, "normalized_rules.json")
    with open(normalized_file, 'w', encoding='utf-8') as f:
        json.dump(all_normalized_rules, f, indent=2, ensure_ascii=False)
    
    training_jsonl = os.path.join(training_dir, "training_samples.jsonl")
    save_jsonl(training_samples, training_jsonl)
    
    openai_samples = []
    for sample in training_samples:
        openai_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a WAF rule generator. Given malicious payload, generate ModSecurity rule structure."
                },
                {
                    "role": "user",
                    "content": f"""Analyze this attack:
Payload: {json.dumps(sample['input']['malicious_payload'])}
Method: {sample['input']['attack_context']['method']}
Location: {', '.join(sample['input']['attack_context']['location'])}

Generate WAF rule."""
                },
                {
                    "role": "assistant",
                    "content": json.dumps(sample['output'])
                }
            ]
        }
        openai_samples.append(openai_format)
    
    openai_file = os.path.join(training_dir, "openai_training.jsonl")
    save_jsonl(openai_samples, openai_file)
    
    # === STATISTICS ===
    print(f"\n📊 Statistics:")
    print(f"  🔷 Total rules (ALL): {total_rules}")
    print(f"  ✅ Rules WITH tests: {total_with_tests}")
    print(f"  ⚠️  Rules WITHOUT tests: {total_without_tests}")
    print(f"  🎯 XSS/SQLi missing tests (valid IDs): {len(rules_without_tests_xss_sqli)}")
    print(f"  📚 Training samples: {len(training_samples)}")
    
    # ✅ Show breakdown by file
    print(f"\n📋 XSS/SQLi Breakdown:")
    for filename in sorted(debug_missing_tests.keys()):
        missing_count = len([rid for rid in debug_missing_tests[filename] if rid and rid.strip()])
        print(f"  {filename}: {missing_count} rules missing tests")
    
    attack_distribution = defaultdict(int)
    for rule in all_normalized_rules:
        for attack_type in rule['attack_info']['type']:
            attack_distribution[attack_type] += 1
    
    print(f"\n🎯 Attack type distribution:")
    for attack_type, count in sorted(attack_distribution.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  {attack_type}: {count}")
    
    print(f"\n✅ Done!")
    print(f"\n📁 Output locations:")
    print(f"  - Raw parsed (ALL): {output_dir}/")
    print(f"  - Training data (ALL): {training_dir}/")
    print(f"  - Manual tests (XSS/SQLi only): {manual_dir}/")

if __name__ == "__main__":
    main()