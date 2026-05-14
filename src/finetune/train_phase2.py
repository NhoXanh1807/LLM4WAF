import json
import os
import random
from pathlib import Path

from config_utils import load_phase_config, resolve_path


CONFIG = load_phase_config("phase2.yaml")
os.environ["CUDA_VISIBLE_DEVICES"] = str(CONFIG.get("gpu", "0"))

from common import run_sft_training


def build_replay_dataset(phase2_observations: Path, phase1_dataset: Path, output_path: Path, replay_ratio: float) -> Path:
    rng = random.Random(42)
    with phase2_observations.open("r", encoding="utf-8") as handle:
        phase2_samples = [json.loads(line) for line in handle if line.strip()]
    with phase1_dataset.open("r", encoding="utf-8") as handle:
        phase1_samples = [json.loads(line) for line in handle if line.strip()]

    replay_count = int(len(phase2_samples) * replay_ratio)
    replay_samples = rng.sample(phase1_samples, min(replay_count, len(phase1_samples)))
    combined = phase2_samples + replay_samples
    rng.shuffle(combined)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for sample in combined:
            handle.write(json.dumps(sample, ensure_ascii=False) + "\n")
    return output_path


def resolve_train_path() -> str:
    train_path = Path(resolve_path(CONFIG["train_path"]))
    if train_path.exists() and not bool(CONFIG.get("regenerate_replay", False)):
        return str(train_path)

    generated = build_replay_dataset(
        phase2_observations=Path(resolve_path(CONFIG["phase2_observations"])),
        phase1_dataset=Path(resolve_path(CONFIG["phase1_dataset"])),
        output_path=Path(resolve_path(CONFIG["generated_train_path"])),
        replay_ratio=float(CONFIG.get("replay_ratio", 0.2)),
    )
    return str(generated)


def main() -> None:
    config = dict(CONFIG)
    config["train_path"] = resolve_train_path()
    config["output_dir"] = resolve_path(config["output_dir"])
    config["adapter_path"] = resolve_path(config["phase1_adapter"])
    if config.get("eval_path"):
        config["eval_path"] = resolve_path(config["eval_path"])
    run_sft_training(
        config
    )


if __name__ == "__main__":
    main()
