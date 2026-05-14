# Gemma 2B Finetune Bundle

Thư mục này là bản rút trích self-contained cho pipeline finetune Gemma 2B gồm 3 phase, lấy từ `LLM4WAF_dungh` nhưng đã được chuẩn hóa lại để chỉ cần làm việc trong chính thư mục `src/finetune`.

## Mục tiêu

- Giữ nguyên các chi tiết cốt lõi của kỹ thuật finetune gốc.
- Gộp lại thành đúng 3 script chính:
  - `train_phase1.py`
  - `train_phase2.py`
  - `train_phase3.py`
- Mỗi phase đọc trực tiếp đúng một file YAML cố định trong `configs/`, không còn đi qua `parse_args`.
- Đưa kèm dữ liệu cần thiết, bundle local DVWA + ModSecurity cho RL, và tài liệu chạy lại.
- Loại bỏ các điểm lệch giữa config và script gốc, đặc biệt ở Phase 2 và Phase 3.

## Cách cấu hình hiện tại

- Script thực thi:
  - `train_phase1.py` -> `configs/phase1.yaml`
  - `train_phase2.py` -> `configs/phase2.yaml`
  - `train_phase3.py` -> `configs/phase3.yaml`
- Nếu cần đổi GPU, output dir, learning rate, WAF URL, replay behavior..., chỉnh trực tiếp YAML tương ứng rồi chạy lại script.

## Trình tự huấn luyện 3 phase

### Phase 1

- Script gốc: `train_red.py`
- Config gốc: `remote_gemma2_2b_phase1.yaml`
- Dataset dùng: `data/processed/phase1_balanced_10k.jsonl`
- Mục tiêu: SFT cơ bản từ prompt sinh payload sang payload né WAF.

Chạy lại bằng bundle này:

```powershell
cd src/finetune
python train_phase1.py
```

Output mặc định:

```text
src/finetune/experiments/remote_gemma2_2b_phase1
```

### Phase 2

- Script gốc: `train_red.py`
- Config gốc: `remote_gemma2_2b_phase2.yaml`
- Ý tưởng cốt lõi: tiếp tục học từ adapter Phase 1, dùng prompt có observations/history và replay buffer để tránh catastrophic forgetting.

Lưu ý quan trọng từ repo gốc:

- Script `create_phase2_with_replay.py` ghi `phase2_with_replay_22k.jsonl` trong comment/tên file, nhưng thuật toán thực tế lấy `20k phase2 + 20% replay = 24k` mẫu.
- Vì vậy bundle này chuẩn hóa theo kết quả thực thi thực tế là `phase2_with_replay_24k.jsonl`.

Chạy lại:

```powershell
cd src/finetune
python train_phase2.py
```

Nếu muốn buộc regenerate replay dataset từ dữ liệu gốc ngay trong bundle:

```powershell
# sửa configs/phase2.yaml
# regenerate_replay: true
python train_phase2.py
```

Output mặc định:

```text
src/finetune/experiments/remote_gemma2_2b_phase2
```

### Phase 3

Nguồn gốc trong repo cũ có 2 nhánh:

- `train_rl_reinforce.py`: khung REINFORCE, stateful env, episode nhiều bước.
- `train_rl_adaptive_pipeline.py`: adaptive probing từ pool payload có nhãn pass/block.

Bundle này hợp nhất 2 ý tưởng đó thành `train_phase3.py`:

- REINFORCE theo episode như script `train_rl_reinforce.py`
- Adaptive probing từ pool payload pass/block như `train_rl_adaptive_pipeline.py`
- Môi trường local WAF/DVWA tự host tại `local_waf/`
- Không còn hardcode config path hoặc hardcode dataset path như script Phase 3 cũ
- Toàn bộ tham số RL được đọc cố định từ `configs/phase3.yaml`

Chạy lại local RL:

```powershell
cd src/finetune\local_waf
docker compose up -d
python setup_dvwa_db.py

cd ..
python train_phase3.py
```

Output mặc định:

```text
src/finetune/experiments/remote_gemma2_2b_phase3_rl
```

## Dữ liệu đã đóng gói trong bundle

### Dùng trực tiếp cho train

- `data/processed/phase1_balanced_10k.jsonl`
- `data/processed/phase2_with_replay_24k.jsonl`

### Dùng để regenerate hoặc làm probe pool

- `data/processed/phase1_passed_only_39k.jsonl`
- `data/processed/phase1_failed_mixed_20k.jsonl`
- `data/processed/phase2_observations_20k.jsonl`
- `data/processed/red_phase3_adaptive_sft.jsonl`

## Vì sao Phase 3 không dùng `red_v40_balanced_final_v13.jsonl`

Trong script gốc `train_rl_adaptive_pipeline.py`, file này bị hardcode nhưng hiện không có trong repo nguồn đang mở. Để tránh tạo một bundle “trông như chạy được nhưng thực ra thiếu dữ liệu”, bản rút trích này thay bằng probe pool khả dụng và có nhãn thật sự trong bundle:

- `phase1_passed_only_39k.jsonl`
- `phase1_failed_mixed_20k.jsonl`
- `phase2_with_replay_24k.jsonl`

Điều này vẫn giữ nguyên cốt lõi kỹ thuật của Phase 3: học tăng cường bằng phản hồi WAF thật, có adaptive probing từ payload pools có nhãn pass/block.

## Yêu cầu môi trường

```powershell
cd src/finetune
pip install -r requirements.txt
```

Thiết lập token Hugging Face:

```powershell
$env:HF_TOKEN="hf_xxx"
```

Hoặc để token tại:

```text
%USERPROFILE%\.cache\huggingface\token
```

## Tệp tham chiếu gốc

Ba file YAML gốc đã được copy vào `reference_configs/` để đối chiếu provenance:

- `reference_configs/remote_gemma2_2b_phase1.yaml`
- `reference_configs/remote_gemma2_2b_phase2.yaml`
- `reference_configs/remote_gemma2_2b_phase3_rl.yaml`

## Kết luận ngắn

Nếu chỉ đứng trong `src/finetune`, bạn có thể:

1. Cài dependencies
2. Chạy Phase 1
3. Chạy Phase 2 từ adapter Phase 1
4. Dựng local DVWA + ModSecurity
5. Chạy Phase 3 RL từ adapter Phase 2

Toàn bộ data flow đã được thống nhất lại theo một bundle duy nhất, không còn phụ thuộc ngược vào `LLM4WAF_dungh`.
