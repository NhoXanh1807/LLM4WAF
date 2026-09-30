
import os
import sys
import json
import tqdm
sys.stdout.reconfigure(encoding='utf-8')

data_dir = os.path.join(os.path.dirname(__file__), 'data')
train_data_dir = os.path.join(os.path.dirname(__file__), 'train_data')
payloads_dir = os.path.join(os.path.dirname(__file__), 'payloads')
train_payloads_dir = os.path.join(os.path.dirname(__file__), 'train_payloads')

# for file in tqdm.tqdm(os.listdir(data_dir)):
#     attack_type = file.split('.')[2]
#     with open(os.path.join(data_dir, file), 'r', encoding='utf-8') as f:
#         payloads = json.load(f)
#     for payload in tqdm.tqdm(payloads):
#         payload_str = payload['payload']
#         if "xss" in attack_type:
#             with open(os.path.join(payloads_dir, f"xss.txt"), 'a', encoding='utf-8') as f:
#                 f.write(payload_str + '\n')
#         elif "sql" in attack_type:
#             with open(os.path.join(payloads_dir, f"sql.txt"), 'a', encoding='utf-8') as f:
#                 f.write(payload_str + '\n')
#         else:
#             with open(os.path.join(payloads_dir, f"other.txt"), 'a', encoding='utf-8') as f:
#                 f.write(payload_str + '\n')



# for file in tqdm.tqdm(os.listdir(train_data_dir)):
#     save_file = "phase1.txt" if "phase1" in file else "phase2.txt"
#     payloads = []
#     with open(os.path.join(train_data_dir, file), 'r', encoding='utf-8') as f:
#         for line in f:
#             payload = json.loads(line)
#             payload_str = payload['messages'][1]['content']
#             payloads.append(payload_str)
#     with open(os.path.join(train_payloads_dir, save_file), 'a', encoding='utf-8') as f:
#         for payload in payloads:
#             f.write(payload + '\n')


train_payloads = {
    "phase1": set(),
    "phase2": set(),
}
with open(os.path.join(train_payloads_dir, "phase1.txt"), 'r', encoding='utf-8') as f:
    for line in f:
        payload = line.strip()
        train_payloads["phase1"].add(payload)
with open(os.path.join(train_payloads_dir, "phase2.txt"), 'r', encoding='utf-8') as f:
    for line in f:
        payload = line.strip()
        train_payloads["phase2"].add(payload)

generated_payloads = {
    "xss": [],
    "sql": [],
}
with open(os.path.join(payloads_dir, "xss.txt"), 'r', encoding='utf-8') as f:
    for line in f:
        payload = line.strip()
        generated_payloads["xss"].append(payload)
with open(os.path.join(payloads_dir, "sql.txt"), 'r', encoding='utf-8') as f:
    for line in f:
        payload = line.strip()
        generated_payloads["sql"].append(payload)

duplicated = {
    "xss": {
        "phase1": [],
        "phase2": [],
    },
    "sql": {
        "phase1": [],
        "phase2": [],
    }
}
dataset_phases = {
    "phase1": "phase1_balanced_10k.jsonl",
    "phase2": "phase2_with_replay_24k.jsonl",
}
for attack_type in ["xss", "sql"]:
    for phase in ["phase1", "phase2"]:
        for payload in train_payloads[phase]:
            if payload in generated_payloads[attack_type]:
                duplicated[attack_type][phase].append(payload)

print(f"Train = {len(train_payloads['phase1']) + len(train_payloads['phase2'])} payloads, Generated = {len(generated_payloads['xss']) + len(generated_payloads['sql'])} payloads")

for attack_type in duplicated:
    total_generated = len(generated_payloads[attack_type])
    total_duplicated = sum(len(duplicated[attack_type][phase]) for phase in duplicated[attack_type])
    rate = (total_duplicated / total_generated) * 100 if total_generated > 0 else 0
    print(f"{attack_type.upper()} : {total_generated} generated payloads, {total_duplicated} duplicated payloads, rate: {rate:.2f}%")
    for phase in duplicated[attack_type]:
        print(f"- {len(duplicated[attack_type][phase])} duplicate{'s' if len(duplicated[attack_type][phase]) != 1 else ''} in fine-tuning dataset '{dataset_phases[phase]}'")