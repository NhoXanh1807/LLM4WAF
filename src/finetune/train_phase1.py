import os
from config_utils import load_phase_config, resolve_path


CONFIG = load_phase_config("phase1.yaml")
os.environ["CUDA_VISIBLE_DEVICES"] = str(CONFIG.get("gpu", "0"))

from common import run_sft_training


def main() -> None:
    config = dict(CONFIG)
    config["train_path"] = resolve_path(config["train_path"])
    config["output_dir"] = resolve_path(config["output_dir"])
    if config.get("adapter_path"):
        config["adapter_path"] = resolve_path(config["adapter_path"])
    if config.get("eval_path"):
        config["eval_path"] = resolve_path(config["eval_path"])
    run_sft_training(
        config
    )


if __name__ == "__main__":
    main()
